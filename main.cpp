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
#include <chrono>

#include <getopt.h>
#include <netdb.h>
#include <signal.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/etharp.h>
#include <netif/ethernet.h>

#include "ethif.h"
#include "main.h"
#include "main.hpp"
#include "mempool.h"

using namespace std;
using std::chrono::steady_clock;

/* eonfigurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

typedef vector<uint8_t> bytes;

/*queue<bytes> input_queue;
cursor input_cursor;
queue<bytes> output_queue;
cursor output_cursor;

mutex input_mutex;
mutex output_mutex;
condition_variable output_condition;*/
#define BUFFER_SIZE (4*1024)

struct ui_input_state {
    FILE* f;
    off_t offset;
    char buffer[BUFFER_SIZE];
};

atomic<bool> connected;

struct tcp_pcb* connection;

ip_addr_t ipaddr;
u16_t port;

struct net_port net_port;

string input_filepath;

struct ether_addr eth_port_mac_address;

bool list_ether_addresses = false;

int
dispatch_netio_thread(struct net_port *ports, int nr_ports, int pkt_burst_sz);
int
dispatch_ui_input(ui_input_state* state);
void ui_thread();
err_t callback_ui_output(void * arg, struct tcp_pcb * tpcb,
                       struct pbuf * p, err_t err);

bool parse_addr(const char* addr, ip_addr_t* ipaddr)
{
    regex ip_regex("(^\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
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

int parse_args(int argc, char** argv, struct net* net_config_out)
{
    char c;
    int count = 0;
    char missing_required_flags[] = "PHampf";

    while ((c = getopt (argc, argv, "P:H:a:m:p:f:L")) != -1) {
        switch (c)
        {
        case 'P':
            port = atoi(optarg);
            count += 2;
            break;
        case 'H':
            if(!parse_addr(optarg, &ipaddr)) {
                fprintf(stderr, "Invalid destination IP Address: %s\n", optarg);
                return -1;
            }
            count += 2;
            break;
        case 'a':
            if(!parse_addr(optarg, &net_config_out->ip_addr)) {
                fprintf(stderr, "Invalid interface IP Address: %s\n", optarg);
                return -1;
            }
            count += 2;
            break;
        case 'm':
            if(!parse_addr(optarg, &net_config_out->netmask)) {
                fprintf(stderr, "Invalid netmask: %s\n", optarg);
                return -1;
            }
            count += 2;
            break;
        case 'p':
            {
                string eth_port_mac_address_str = optarg;
                auto erase_iter = remove(eth_port_mac_address_str.begin(), eth_port_mac_address_str.end(), ':');
                eth_port_mac_address_str.erase(erase_iter, eth_port_mac_address_str.end());
                if(eth_port_mac_address_str.size() != ETHER_ADDR_LEN*2) {
                    fprintf(stderr, "Invalid length for ether MAC: %s\n", optarg);
                    return -1;
                }
                for(unsigned int i = 0; i < ETHER_ADDR_LEN; i++) {
                    char* end_str;
                    string byte = eth_port_mac_address_str.substr(i*2, 2);
                    eth_port_mac_address.addr_bytes[i] = strtol(byte.c_str(), &end_str, 16);
                    if(end_str == byte.c_str()) {
                        fprintf(stderr, "Invalid ether MAC: %s\n", optarg);
                        return -1;
                    }
                }
            }
            count += 2;
            break;
        case 'f':
            input_filepath = optarg;
            count += 2;
            break;
        case 'L':
            list_ether_addresses = true;
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
    if(missing_flag != '\0' && !list_ether_addresses) {
        fprintf(stderr, "Missing required flag -%c\n", missing_flag);
        return -1;
    }

    return count;
}

#define IP4_OR_NULL(ip_addr) ((ip_addr).addr == IPADDR_ANY ? 0 : &(ip_addr))

static int
create_eth_port(struct net_port *net_port, int socket_id)
{
    struct net *net = &net_port->net;
    struct rte_port_eth_params params = {};

    params.port_id = net->port_id;
    params.nb_rx_desc = RTE_TEST_RX_DESC_DEFAULT;
    params.nb_tx_desc = RTE_TEST_TX_DESC_DEFAULT;
    params.mempool = pktmbuf_pool;
    params.eth_conf.link_speeds = ETH_LINK_SPEED_AUTONEG;


    struct ethif *ethif;
    struct netif *netif;

    ethif = ethif_alloc(socket_id);
    if (ethif == NULL)
        rte_exit(EXIT_FAILURE, "Cannot alloc eth port\n");

    if (ethif_init(ethif, &params, socket_id, net_port) != ERR_OK)
        rte_exit(EXIT_FAILURE, "Cannot init eth port\n");

    struct ether_addr mac_addr;
    rte_eth_macaddr_get(net_port->net.port_id, &mac_addr);

    netif = &ethif->netif;

    memcpy(netif->hwaddr, mac_addr.addr_bytes, ETHER_ADDR_LEN);
    netif->hwaddr_len = ETHER_ADDR_LEN;

    rte_eth_promiscuous_enable(net_port->net.port_id);

    netif_add(netif,
          IP4_OR_NULL(net->ip_addr),
          IP4_OR_NULL(net->netmask),
          IP4_OR_NULL(net->gw),
          ethif,
          ethif_added_cb,
          ethernet_input);

    netif_set_link_up(netif);
    netif_set_up(netif);

    return 0;
}

volatile static sig_atomic_t quit = 0;
void interrupt_handler(int sig){
    quit = 1; // set flag
}

int main(int argc, char** argv) {
    int ret;

    int nr_ports; //TODO

    signal(SIGINT, interrupt_handler);

    lwip_init();

    //parse command line arguments for app
    ret = parse_args(argc, argv, &net_port.net);

    if(ret < 0) {
        rte_exit(EXIT_FAILURE, "Invalid arguments\n");
    }

    argc -= ret;
    argv += ret;

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
    
    if(list_ether_addresses) {
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
        
        if(memcmp(eth_port_mac_address.addr_bytes, mac_addr.addr_bytes, ETHER_ADDR_LEN) == 0) {
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
    net_port.net.port_id = (uint8_t)found_eth_port_for_mac;

    mempool_init(rte_socket_id());

    if(net_port.net.port_id >= nr_eth_dev) {
        rte_exit(EXIT_FAILURE, "Invalid ethernet device\n");
    }

    create_eth_port(&net_port, 0);

    //static ARP entry for testing
    ip_addr_t arp_ipaddr;
    struct eth_addr arp_ethaddr = {
        .addr = {0x68, 0x05, 0xca, 0x3a, 0xa3, 0x5c}
    };
    parse_addr("10.1.0.2", &arp_ipaddr);

    etharp_add_static_entry(&arp_ipaddr, &arp_ethaddr);

    RTE_LOG(INFO, APP, "Created eth port with ID %d\n", net_port.net.port_id);
    RTE_LOG(INFO, APP, "\tIP: %s\n", ipaddr_ntoa(&net_port.net.ip_addr));
    RTE_LOG(INFO, APP, "\tNetmask: %s\n", ipaddr_ntoa(&net_port.net.netmask));

    RTE_LOG(INFO, APP, "Binding port...\n");
    connection = tcp_new();
    err_t tcp_ret;
    tcp_ret = tcp_bind(connection, &net_port.net.ip_addr, rand() % 1000 + 3000 /* bind to some random default port */);
    if(tcp_ret != ERR_OK) {
        RTE_LOG(ERR, APP, "Failed to bind connection: %d\n", tcp_ret);
    }
    RTE_LOG(INFO, APP, "Setting up connecting...\n");

    tcp_ret = tcp_connect(connection, &ipaddr, port, [](void* arg, struct tcp_pcb*, err_t err) -> err_t {
        if(err == ERR_OK) {
            RTE_LOG(INFO, APP, "Established connection\n");
            connected = true;
        }
        else {
            RTE_LOG(ERR, APP, "Connecting failed (%d)\n", err);
        }

        return ERR_OK;
    });
    tcp_recv(connection, callback_ui_output);

    struct net_port ports[1] = {
        net_port,
    };

    RTE_LOG(INFO, APP, "Starting net io input loop...\n");
    dispatch_netio_thread(ports, 1, PKT_BURST_SZ);
    RTE_LOG(INFO, APP, "Net io input finished\n");

    rte_exit(EXIT_SUCCESS, "Finished\n");
}


static int
dispatch_to_ethif(struct netif *netif,
          struct rte_mbuf **pkts, uint32_t n_pkts)
{
    struct ethif *ethif = (struct ethif *)netif->state;
    uint32_t i;

    for (i = 0; i < n_pkts; i++)
        ethif_input(ethif, pkts[i]);

    return n_pkts;
}

static int
dispatch(struct net_port *ports, int nr_ports,
     struct rte_mbuf **pkts, uint32_t pkt_burst_sz)
{
    struct net_port *net_port;
    struct rte_port *rte_port;
    struct netif *netif;
    int i;
    uint32_t n_pkts;

    //static auto last_time_called = steady_clock::now();

    /*
     * From lwip/src/core/timers.c:
     *
     * "Must be called periodically from your main loop."
     */
    sys_check_timeouts();

    for (i = 0; i < nr_ports; i++) {
        net_port = &ports[i];
        rte_port = net_port->rte_port;

        n_pkts = rte_port->ops.rx_burst(rte_port, pkts, pkt_burst_sz);
        if (unlikely(n_pkts > pkt_burst_sz)) {
            printf("n_pkts > pkt_burst_sz\n");
            continue;
        }

        /*if (n_pkts == 0) {
            printf("[%s] n_pkts == 0\n", TIMESTR());
            continue;
        }*/

        //auto duration_since_last_called = steady_clock::now() - last_time_called;
        //double duration_since_last_called_msec = std::chrono::duration_cast<std::chrono::milliseconds>(duration_since_last_called).count();
        //if(duration_since_last_called_msec > 500.0) {
        //    printf("Not called since %g msec\n", duration_since_last_called_msec);
        //}
        //last_time_called = steady_clock::now();

        netif = net_port->netif;
        dispatch_to_ethif(netif, pkts, n_pkts);
    }
    return 0;
}

int
dispatch_netio_thread(struct net_port *ports, int nr_ports, int pkt_burst_sz)
{
    struct rte_mbuf *pkts[pkt_burst_sz];
    int ret_dispatch = 0;
    int ret_io = 0;
    ui_input_state input_state = {0};

    while (!quit) {
        ret_dispatch = dispatch(ports, nr_ports, pkts, pkt_burst_sz);
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
    //static auto last_time_send = steady_clock::now();

    if(state->f == NULL) {
        if(input_filepath == "-") {
            state->f = stdin;
        }
        else {
            state->f = fopen(input_filepath.c_str(), "r");
        }

        if(state->f == NULL) {
            printf("failed to open source file\n");
            return -1;
        }
    }

    if(!feof(state->f)) {
        u16_t available = tcp_sndbuf(connection);
        if(available == 0) {
            //printf("no space in queue left\n");
            return 0; //back off and try again later
        }
        u16_t send_count = min(available, (u16_t)BUFFER_SIZE);

        if(send_count == 0) {
            return 0;
        }

        //auto duration_since_last_send = steady_clock::now() - last_time_send;
        //double duration_since_last_send_msec = std::chrono::duration_cast<std::chrono::milliseconds>(duration_since_last_send).count();
        //if(duration_since_last_send_msec > 500.0) {
        //    printf("No data send since %g msec\n", duration_since_last_send_msec);
        //}
        //last_time_send = steady_clock::now();

        //printf("trying to read %d bytes ", (int)send_count);
        size_t bytes_read = fread(state->buffer, 1, send_count, state->f);
        
        //printf("and read %d bytes, sending now...", (int)bytes_read);
        int flags = TCP_WRITE_FLAG_COPY;
        if(bytes_read == send_count) {
            flags |= TCP_WRITE_FLAG_MORE;
        }
        tcp_write(connection, state->buffer, (u16_t)bytes_read, flags);
        tcp_output(connection);

        //printf("done\n");

        return 0;
    }
    else {
        printf("closing connection\n");
        connected = false;
        tcp_close(connection);

        return -2;
    }
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
        tcp_recved(tpcb, p->len);
    }
    else {
        //p is NULL when the connection has been finally closed
        printf("connection has been closed\n");
    }

    return 0;
}
