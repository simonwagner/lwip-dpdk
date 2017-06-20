#include <queue>
#include <thread>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <regex>
#include <algorithm>
#include <unistd.h>
#include <atomic>

#include <getopt.h>
#include <netdb.h>
#include <signal.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "context.h"
#include "ethif.h"
#include "main.h"
#include "main.hpp"
#include "mempool.h"
#include "tools.h"

using namespace std;


#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

#define BUFFER_SIZE (4*1024)

struct ui_input_state {
    string input_filepath;
    FILE* f;
    off_t offset;
    char buffer[BUFFER_SIZE];
};

atomic<bool> connected;

struct tcp_pcb* connection;

struct program_args {
    uint8_t		      port_id;
    ip_addr_t	      ip_addr;
    ip_addr_t	      netmask;
    struct ether_addr eth_port_mac_address;
    bool              list_ether_addresses;
    string            input_filepath;
    ip_addr_t         dest_ip;
    uint16_t          dest_port;
};

static duration duration_bytes_sent;

static struct lwip_dpdk_global_context* global_context;
static struct lwip_dpdk_context* context;

int
dispatch_netio_thread(netif *netif, int pkt_burst_sz, string input_file);
int
dispatch_ui_input(ui_input_state* state);
void ui_thread();
err_t callback_ui_output(void * arg, struct tcp_pcb * tpcb,
                       struct pbuf * p, err_t err);
err_t callback_sent(void * arg, struct tcp_pcb * tpcb,
                   u16_t len);

bool parse_addr(const char* addr, ip_addr_t* ipaddr)
{
    regex ip_regex(R"(^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$)");
    cmatch match;

    if(regex_match(addr, match, ip_regex)) {
        IP_ADDR4(ipaddr,
                 atoi(match[1].str().c_str()),
                 atoi(match[2].str().c_str()),
                 atoi(match[3].str().c_str()),
                 atoi(match[4].str().c_str()));
        return true;
    }
    else {
        return false;
    }
}

void strrplchr(char* str, char c, char rplc)
{
    for(size_t i = 0; str[i] != '\0'; i++) {
        if(str[i] == c) {
            str[i] = rplc;
        }
    }
}

char streqchr(char* str, char c)
{
    for(size_t i = 0; str[i] != '\0'; i++) {
        if(str[i] != c) {
            return str[i];
        }
    }

    return '\0';
}

int parse_args(int argc, char** argv, struct program_args*  args_out)
{
    char c;
    int count = 0;
    char missing_required_flags[] = "PHampf";

    args_out->list_ether_addresses = false;

    while ((c = getopt (argc, argv, "P:H:a:m:p:f:L")) != -1) {
        switch (c)
        {
        case 'P':
            args_out->dest_port = atoi(optarg);
            count += 2;
            break;
        case 'H':
            if(!parse_addr(optarg, &args_out->dest_ip)) {
                fprintf(stderr, "Invalid destination IP Address: %s\n", optarg);
                return -1;
            }
            count += 2;
            break;
        case 'a':
            if(!parse_addr(optarg, &args_out->ip_addr)) {
                fprintf(stderr, "Invalid interface IP Address: %s\n", optarg);
                return -1;
            }
            count += 2;
            break;
        case 'm':
            if(!parse_addr(optarg, &args_out->netmask)) {
                fprintf(stderr, "Invalid netmask: %s\n", optarg);
                return -1;
            }
            count += 2;
            break;
        case 'p':
            {
                string eth_port_mac_address_str = optarg;
                memset(args_out->eth_port_mac_address.addr_bytes, 0, ETHER_ADDR_LEN);

                //delete : seperator if it exists
                auto erase_iter = remove(eth_port_mac_address_str.begin(), eth_port_mac_address_str.end(), ':');
                eth_port_mac_address_str.erase(erase_iter, eth_port_mac_address_str.end());

                if(eth_port_mac_address_str.size() != ETHER_ADDR_LEN*2) {
                    fprintf(stderr, "Invalid length for ether MAC: %s\n", optarg);
                    return -1;
                }

                //parse and read MAC address
                for(unsigned int i = 0; i < ETHER_ADDR_LEN; i++) {
                    char* end_str;
                    string byte = eth_port_mac_address_str.substr(i*2, 2);
                    args_out->eth_port_mac_address.addr_bytes[i] = strtol(byte.c_str(), &end_str, 16);
                    if(end_str == byte.c_str()) {
                        fprintf(stderr, "Invalid ether MAC: %s\n", optarg);
                        return -1;
                    }
                }
            }
            count += 2;
            break;
        case 'f':
            args_out->input_filepath = optarg;
            count += 2;
            break;
        case 'L':
            args_out->list_ether_addresses = true;
            count += 1;
            break;
        case '?':
            if (optopt == 'c')
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
            else if (isprint (optopt))
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            else
                fprintf (stderr,
                       "Unknown option character `\\x%x'.\n",
                       optopt);
            return -1;
        default:
            return -1;
        }

        strrplchr(missing_required_flags, c, '-');
    }

    char missing_flag = streqchr(missing_required_flags, '-');
    if(missing_flag != '\0' && !args_out->list_ether_addresses) {
        fprintf(stderr, "Missing required flag -%c\n", missing_flag);
        return -1;
    }

    return count;
}

static int
create_eth_port(struct netif *netif, int socket_id, int port_id, ip_addr_t *ip_addr, ip_addr_t *netmask, ip_addr_t *gw)
{
    struct lwip_dpdk_port_eth *port = NULL;
    struct lwip_dpdk_queue_eth *queue = NULL;
    struct lwip_dpdk_port_eth_params params = {};

    params.port_id = port_id;
    params.nb_rx_desc = RTE_TEST_RX_DESC_DEFAULT;
    params.nb_tx_desc = RTE_TEST_TX_DESC_DEFAULT;
    params.eth_conf.link_speeds = ETH_LINK_SPEED_AUTONEG;

    memset(netif, 0, sizeof(struct netif));

    port = lwip_dpdk_port_eth_create(&params);
    if(port == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot alloc eth port\n");
    }

    queue = ethif_queue_create(context, port, socket_id, 0);
    if(queue == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot alloc eth queue\n");
    }

    if(lwip_dpdk_port_eth_start(port) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot start port\n");
    }

    context->api->_netif_add(netif,
          ip_addr,
          netmask,
          gw,
          queue,
          ethif_queue_added_cb,
          context->api->_ethernet_input);

    context->api->_netif_set_link_up(netif);
    context->api->_netif_set_up(netif);

    return 0;
}

volatile static sig_atomic_t quit = 0;
void interrupt_handler(int sig){
    quit = 1; // set flag
}

int main(int argc, char** argv) {
    int ret;
    struct netif netif;
    struct program_args args;

    signal(SIGINT, interrupt_handler);

    global_context = lwip_dpdk_init();

    //parse command line arguments for app
    ret = parse_args(argc, argv, &args);

    if(ret < 0) {
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");
    }

    argc -= ret;
    argv += ret;
    if(argc > 1 && strcmp(argv[1], "--") == 0) {
        //support seperation of EAL arguments by --
        argc -= 1;
        argv += 1;
    }

    //parse command line args for dpdk
    RTE_LOG(INFO, APP, "Setting up dpdk...\n");
    ret = rte_eal_init(argc, argv);
    if(ret < 0) {
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    }

    if(rte_eal_pci_probe() < 0) {
        rte_exit(EXIT_FAILURE, "Cannot probe PCI\n");
    }

    int nr_eth_dev = rte_eth_dev_count();
    
    RTE_LOG(INFO, APP, "Found %d ethernet devices\n", nr_eth_dev);
    
    if(args.list_ether_addresses) {
        for(uint8_t i = 0; i < nr_eth_dev; i++) {
            struct ether_addr mac_addr;
            rte_eth_macaddr_get(i, &mac_addr);
            
            char buffer[ETHER_ADDR_FMT_SIZE];
            ether_format_addr(buffer, ETHER_ADDR_FMT_SIZE, &mac_addr);
            
            struct rte_eth_dev_info dev_info;
            rte_eth_dev_info_get(i, &dev_info);
            
            struct rte_pci_addr *addr = NULL;
            char pci_addr[13] = "0000:00:00.0";
            
            printf("- [% 3d] %s\n", i, buffer);
            
            if (dev_info.pci_dev) {
                addr = &dev_info.pci_dev->addr;
                sprintf(pci_addr, "%04x:%02x:%02x.%01x",
                        addr->domain, addr->bus, addr->devid, addr->function);
            }
            
            if (strncmp("0000:00:00.0", pci_addr, 12))
                printf("\tPCI address: %s\n", pci_addr);
            else
                printf("\tPCI address: N/A\n");
        }
        
        rte_exit(EXIT_SUCCESS, "Finished listing available ethernet devices\n");
    }
    
    int found_eth_port_for_mac = -1;
    for(uint8_t i = 0; i < nr_eth_dev; i++) {
        struct ether_addr mac_addr;
        rte_eth_macaddr_get(i, &mac_addr);
        
        printf("Found network port with MAC:");
        for(int i=0; i < ETHER_ADDR_LEN; i++) {
            printf("%X", mac_addr.addr_bytes[i]);
        }
        printf("\n");
        
        if(memcmp(args.eth_port_mac_address.addr_bytes, mac_addr.addr_bytes, ETHER_ADDR_LEN) == 0) {
            found_eth_port_for_mac = i;

            struct rte_eth_dev_info dev_info;
            rte_eth_dev_info_get(i, &dev_info);
            struct rte_pci_addr *addr = NULL;
            char pci_addr[13] = "0000:00:00.0";

            if (dev_info.pci_dev) {
                addr = &dev_info.pci_dev->addr;
                sprintf(pci_addr, "%04x:%02x:%02x.%01x",
                        addr->domain, addr->bus, addr->devid, addr->function);
            }
            printf("Selected port %d at PCI address %s\n", found_eth_port_for_mac, pci_addr);
        }
    }
    
    if(found_eth_port_for_mac < 0) {
        rte_exit(EXIT_FAILURE, "Requested ethernet device not found\n");
    }

    uint8_t port_id = (uint8_t)found_eth_port_for_mac;

    context = lwip_dpdk_context_create(global_context, 0, NULL);
    if(context == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to create context\n");
    }

    lwip_dpdk_pktmbuf_pool_create_all(rte_socket_id());

    if(port_id >= nr_eth_dev) {
        rte_exit(EXIT_FAILURE, "Invalid ethernet device\n");
    }

    create_eth_port(&netif, rte_socket_id(), port_id, &args.ip_addr, &args.netmask, NULL);
    struct lwip_dpdk_queue_eth* ethif = netif_dpdk_ethif(&netif);

    //static ARP entry for testing
    /*ip_addr_t arp_ipaddr;
    struct eth_addr arp_ethaddr = {
        .addr = {0x68, 0x05, 0xca, 0x3a, 0xa3, 0x5c}
    };
    parse_addr("10.1.0.2", &arp_ipaddr);

    etharp_add_static_entry(&arp_ipaddr, &arp_ethaddr);*/

    RTE_LOG(INFO, APP, "Created eth port with ID %d\n", ethif->eth_port->port_id);
    RTE_LOG(INFO, APP, "\tIP: %s\n", context->api->ip4addr_ntoa(&netif.ip_addr));
    RTE_LOG(INFO, APP, "\tNetmask: %s\n", context->api->ip4addr_ntoa(&netif.netmask));

    RTE_LOG(INFO, APP, "Binding port...\n");
    connection = context->api->tcp_new();
    err_t tcp_ret;
    tcp_ret = context->api->_tcp_bind(connection, &netif.ip_addr, rand() % 1000 + 3000 /* bind to some random default port */);
    if(tcp_ret != ERR_OK) {
        RTE_LOG(ERR, APP, "Failed to bind connection: %d\n", tcp_ret);
    }
    RTE_LOG(INFO, APP, "Setting up connecting...\n");

    context->api->tcp_sent(connection, callback_sent); //set callback for acknowledgment
    tcp_ret = context->api->_tcp_connect(connection, &args.dest_ip, args.dest_port, [](void* arg, struct tcp_pcb*, err_t err) -> err_t {
        if(err == ERR_OK) {
            RTE_LOG(INFO, APP, "Established connection\n");
            connected = true;
        }
        else {
            RTE_LOG(ERR, APP, "Connecting failed (%d)\n", err);
        }

        return ERR_OK;
    });
    context->api->tcp_recv(connection, callback_ui_output);

    RTE_LOG(INFO, APP, "Starting net io input loop...\n");
    dispatch_netio_thread(&netif, PKT_BURST_SZ, args.input_filepath);
    RTE_LOG(INFO, APP, "Net io input finished\n");

    lwip_dpdk_close(global_context);
    rte_exit(EXIT_SUCCESS, "Finished\n");
}


static int
dispatch_to_ethif(struct netif *netif,
          struct rte_mbuf **pkts, uint32_t n_pkts)
{
    uint32_t i;

    for (i = 0; i < n_pkts; i++)
        ethif_queue_input(netif, pkts[i]);

    return n_pkts;
}

static int
dispatch(struct netif *netif, struct rte_mbuf **pkts, uint32_t pkt_burst_sz)
{
    struct lwip_dpdk_queue_eth* lwip_dpdk_queue = netif_dpdk_ethif(netif);
    uint32_t n_pkts;

    /*
     * From lwip/src/core/timers.c:
     *
     * "Must be called periodically from your main loop."
     */
    context->api->sys_check_timeouts();

    n_pkts = lwip_dpdk_queue->ops.rx_burst(lwip_dpdk_queue, pkts, pkt_burst_sz);
    if (unlikely(n_pkts > pkt_burst_sz)) {
        printf("n_pkts > pkt_burst_sz\n");
        return 0;
    }

    dispatch_to_ethif(netif, pkts, n_pkts);

    return 0;
}

int
dispatch_netio_thread(struct netif *netif, int pkt_burst_sz, string input_filepath)
{
    struct rte_mbuf *pkts[pkt_burst_sz];
    int ret_dispatch = 0;
    int ret_io = 0;
    ui_input_state input_state = {};

    input_state.input_filepath = input_filepath;

    duration_start(&duration_bytes_sent);

    while (!quit) {
        ret_dispatch = dispatch(netif, pkts, pkt_burst_sz);
        if(ret_dispatch < 0) {
            break;
        }

        if(connected) {
            ret_io = dispatch_ui_input(&input_state);
        }
    }
    return 0;
}

int
dispatch_ui_input(ui_input_state* state)
{
    if(state->f == NULL) {
        if(state->input_filepath == "-") {
            state->f = stdin;
        }
        else {
            state->f = fopen(state->input_filepath.c_str(), "r");
        }

        if(state->f == NULL) {
            printf("failed to open source file\n");
            return -1;
        }
    }

    if(!feof(state->f)) {
        u16_t available = tcp_sndbuf(connection);
        if(available == 0) {
            return 0; //back off and try again later
        }
        u16_t send_count = min(available, (u16_t)BUFFER_SIZE);

        if(send_count == 0) {
            return 0;
        }

        size_t bytes_read = fread(state->buffer, 1, send_count, state->f);
        
        int flags = TCP_WRITE_FLAG_COPY;
        if(bytes_read == send_count) {
            flags |= TCP_WRITE_FLAG_MORE;
        }
        context->api->tcp_write(connection, state->buffer, (u16_t)bytes_read, flags);
        context->api->tcp_output(connection);

        return 0;
    }
    else {
        printf("closing connection\n");
        connected = false;
        context->api->tcp_close(connection);

        return -2;
    }
}

err_t callback_sent(void * arg, struct tcp_pcb * tpcb,
                   u16_t len)
{
    static uint64_t sum_bytes_sent = 0;

    sum_bytes_sent += len;

    if(sum_bytes_sent % (10ULL*1024ULL*1024ULL) == 0 && sum_bytes_sent > 0) {
        duration_stop(&duration_bytes_sent);

        printf("\033[A\033[2KSpeed: %f MBits/s\n", sum_bytes_sent*8.0 / duration_as_sec(&duration_bytes_sent) / (1e6));

        sum_bytes_sent = 0;
        duration_start(&duration_bytes_sent);
    }

    return ERR_OK;
}

err_t callback_ui_output(void * arg, struct tcp_pcb * tpcb,
                       struct pbuf * p, err_t err)
{
    if(err != ERR_OK) {
        return err;
    }

    //do nothing with the data we receive

    //acknowledge that we received the data
    if(p != NULL) {
        context->api->tcp_recved(tpcb, p->len);
    }
    else {
        //p is NULL when the connection has been finally closed
        printf("connection has been closed\n");
    }

    return 0;
}
