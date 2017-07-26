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
#include <algorithm>

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

#define BUFFER_SIZE (4*1024)

struct ui_input_state {
    string input_filepath = "";
    FILE* f = NULL;
    off_t offset = 0;
    char buffer[BUFFER_SIZE];
    struct tcp_pcb* connection = NULL;
    bool connected = false;
    struct lwip_dpdk_context* context = NULL;

};

struct program_args {
    uint8_t		      port_id;
    ip_addr_t	      ip_addr;
    ip_addr_t	      netmask;
    struct ether_addr eth_port_mac_address;
    bool              list_ether_addresses;
    string            input_filepath;
    ip_addr_t         dest_ip;
    uint16_t          dest_port;
    int               number_of_connections;
    int               number_of_cores;
};

struct main_core_args {
    struct program_args* args;
    struct lwip_dpdk_context* context;
};

static duration duration_bytes_sent;

static struct lwip_dpdk_global_context* global_context;

int
dispatch_netio_thread(struct ui_input_state *input_states, struct lwip_dpdk_context *context, int number_of_connections);
int
dispatch_ui_input(ui_input_state* state);
void ui_thread();
err_t callback_ui_output(void * arg, struct tcp_pcb * tpcb,
                       struct pbuf * p, err_t err);
err_t callback_sent(void * arg, struct tcp_pcb * tpcb,
                   u16_t len);
int main_core(void* arg);

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
    args_out->number_of_connections = 1;
    args_out->number_of_cores = 1;

    while ((c = getopt (argc, argv, "P:H:a:m:p:f:L:n:c:")) != -1) {
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
        case 'n':
            args_out->number_of_connections = atoi(optarg);
            count += 2;
            break;
        case 'c':
            args_out->number_of_cores = atoi(optarg);
            count += 2;
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

volatile static sig_atomic_t quit = 0;
void interrupt_handler(int sig){
    quit = 1; // set flag
}

int main(int argc, char** argv) {
    int ret;
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
    if(port_id >= nr_eth_dev) {
        rte_exit(EXIT_FAILURE, "Invalid ethernet device\n");
    }

    struct lwip_dpdk_context* contexts[args.number_of_cores];
    for(int c = 0; c < args.number_of_cores; ++c) {
        struct lwip_dpdk_context* context = lwip_dpdk_context_create(global_context, 0);
        if(context == NULL) {
            rte_exit(EXIT_FAILURE, "Failed to create context\n");
        }
        contexts[c] = context;
    }


    struct lwip_dpdk_global_netif* global_netif = lwip_dpdk_global_netif_create(global_context, port_id, &args.ip_addr, &args.netmask, &lwip_dpdk_ip_addr_any);

    //static ARP entry for testing
    /*ip_addr_t arp_ipaddr;
    struct eth_addr arp_ethaddr = {
        .addr = {0x68, 0x05, 0xca, 0x3a, 0xa3, 0x5c}
    };
    parse_addr("10.1.0.2", &arp_ipaddr);

    etharp_add_static_entry(&arp_ipaddr, &arp_ethaddr);*/

    RTE_LOG(INFO, APP, "Created eth port with ID %d\n", (int)lwip_dpdk_global_netif_get_port(global_netif));
    RTE_LOG(INFO, APP, "\tIP: %s\n", contexts[0]->api->ip4addr_ntoa(lwip_dpdk_global_netif_get_ipaddr(global_netif)));
    RTE_LOG(INFO, APP, "\tNetmask: %s\n", contexts[0]->api->ip4addr_ntoa(lwip_dpdk_global_netif_get_netmask(global_netif)));

    RTE_LOG(INFO, APP, "Configuration is finished, starting lwip-dpdk machinery...\n");
    if(lwip_dpdk_start(global_context) < 0) {
        rte_exit(EXIT_FAILURE, "failed to start lwip-dpdk");
    }

    struct main_core_args main_core_args[args.number_of_cores];
    for(int c = 0; c < args.number_of_cores; ++c) {
        main_core_args[c].args = &args;
        main_core_args[c].context = contexts[c];
    }

    for(int c = 0; c < args.number_of_cores; ++c) {
        RTE_LOG(INFO, APP, "Launching core %d...\n", c);
        rte_eal_remote_launch(main_core, &main_core_args[c], c + 1);
    }

    for(int c = 0; c < args.number_of_cores; ++c) {
        rte_eal_wait_lcore(c+1);
    }

    lwip_dpdk_close(global_context);
    rte_exit(EXIT_SUCCESS, "Finished\n");
}

int main_core(void* arg) {
    struct main_core_args* main_core_args = (struct main_core_args*)arg;
    struct program_args* args = main_core_args->args;
    struct lwip_dpdk_context* context = main_core_args->context;

    RTE_LOG(INFO, APP, "Running context %d (%p) on lcore %d\n", context->index, context, rte_lcore_id());

    int number_of_connections = args->number_of_connections;
    struct ui_input_state* input_states = new ui_input_state[number_of_connections];
    struct tcp_pcb** connections = (struct tcp_pcb**)calloc(number_of_connections, sizeof(struct tcp_pcb*));

    for(int i = 0; i < number_of_connections; i++) {
        RTE_LOG(INFO, APP, "Creating connection %d of %d...\n", i + 1, number_of_connections);
        struct tcp_pcb* connection = context->api->tcp_new();

        input_states[i].input_filepath = args->input_filepath;
        input_states[i].context = context;

        context->api->tcp_arg(connection, &input_states[i]);

        err_t tcp_ret;
        RTE_LOG(INFO, APP, "Setting up connecting...\n");

        context->api->tcp_sent(connection, callback_sent); //set callback for acknowledgment
        tcp_ret = context->api->_tcp_connect(connection, &args->dest_ip, args->dest_port, [](void* arg, struct tcp_pcb* pcb, err_t err) -> err_t {
            struct ui_input_state* input_state = (struct ui_input_state*)arg;
            struct lwip_dpdk_context* context = input_state->context;

            if(err == ERR_OK) {
                input_state->connected = true;
                RTE_LOG(INFO, APP, "Established connection from port %d to %s, src port %d\n", pcb->local_port, context->api->ip4addr_ntoa(&pcb->remote_ip), pcb->remote_port);
            }
            else {
                RTE_LOG(ERR, APP, "Connecting failed (%d)\n", err);
            }

            return ERR_OK;
        });
        if(tcp_ret != ERR_OK) {
            rte_exit(EXIT_FAILURE, "failed to connect");
        }
        context->api->tcp_recv(connection, callback_ui_output);
        connections[i] = connection;

        input_states[i].connection = connections[i];
    }

    RTE_LOG(INFO, APP, "Starting net io input loop...\n");
    dispatch_netio_thread(input_states, context, number_of_connections);
    RTE_LOG(INFO, APP, "Net io input finished\n");

    return 0;
}

int
dispatch_netio_thread(struct ui_input_state* input_states, struct lwip_dpdk_context* context, int number_of_connections)
{
    duration_start(&duration_bytes_sent);

    while (!quit) {
        lwip_dpdk_context_dispatch_input(context);

        for(int i = 0; i < number_of_connections; i++) {
            if(input_states[i].connected) {
                dispatch_ui_input(&input_states[i]);
            }
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
        u16_t available = tcp_sndbuf(state->connection);

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

        state->context->api->tcp_write(state->connection, state->buffer, (u16_t)bytes_read, flags);
        state->context->api->tcp_output(state->connection);

        return 0;
    }
    else {
        printf("closing connection\n");
        state->connected = false;
        state->context->api->tcp_close(state->connection);

        return -2;
    }
}

err_t callback_sent(void * arg, struct tcp_pcb * tpcb,
                   u16_t len)
{
    static uint64_t sum_bytes_sent = 0;

    sum_bytes_sent += len;

    if(sum_bytes_sent > 10ULL*1024ULL*1024ULL) {
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
    struct ui_input_state* input_state = (struct ui_input_state*)arg;

    if(err != ERR_OK) {
        return err;
    }

    //do nothing with the data we receive

    //acknowledge that we received the data
    if(p != NULL) {
        input_state->context->api->tcp_recved(tpcb, p->len);
    }
    else {
        //p is NULL when the connection has been finally closed
        printf("connection has been closed\n");
    }

    return 0;
}
