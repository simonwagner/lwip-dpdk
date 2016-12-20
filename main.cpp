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

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include <lwip/init.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <netif/ethernet.h>

#include "ethif.h"
#include "main.h"
#include "main.hpp"
#include "mempool.h"

using namespace std;

/* eonfigurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

typedef vector<uint8_t> bytes;

queue<bytes> input_queue;
cursor input_cursor;
queue<bytes> output_queue;
cursor output_cursor;

mutex input_mutex;
mutex output_mutex;
condition_variable output_condition;

atomic<bool> connected;

struct tcp_pcb* connection;

ip_addr_t ipaddr;
u16_t port;

struct net_port net_port;

int
dispatch_netio_thread(struct net_port *ports, int nr_ports, int pkt_burst_sz);
int
dispatch_ui_input();
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
    char missing_required_flags[] = "PHamp";

    while ((c = getopt (argc, argv, "P:H:a:m:p:")) != -1) {
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
            net_config_out->port_id = atoi(optarg);
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
    if(missing_flag != '\0') {
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
    struct rte_port_eth_params params;

    params.port_id = net->port_id;
    params.nb_rx_desc = RTE_TEST_RX_DESC_DEFAULT;
    params.nb_tx_desc = RTE_TEST_TX_DESC_DEFAULT;
    params.mempool = pktmbuf_pool;


    struct ethif *ethif;
    struct netif *netif;

    ethif = ethif_alloc(socket_id);
    if (ethif == NULL)
        rte_exit(EXIT_FAILURE, "Cannot alloc eth port\n");

    if (ethif_init(ethif, &params, socket_id, net_port) != ERR_OK)
        rte_exit(EXIT_FAILURE, "Cannot init eth port\n");

    netif = &ethif->netif;
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

int main(int argc, char** argv) {
    int ret;

    int nr_ports; //TODO


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

    mempool_init(rte_socket_id());

    if(net_port.net.port_id >= nr_eth_dev) {
        rte_exit(EXIT_FAILURE, "Invalid ethernet device\n");
    }

    create_eth_port(&net_port, 0);
    RTE_LOG(INFO, APP, "Created eth port with ID %d\n", net_port.net.port_id);
    RTE_LOG(INFO, APP, "\tIP: %s\n", ipaddr_ntoa(&net_port.net.ip_addr));
    RTE_LOG(INFO, APP, "\tNetmask: %s\n", ipaddr_ntoa(&net_port.net.netmask));

    RTE_LOG(INFO, APP, "Setting up connection\n");
    connection = tcp_new();
    err_t tcp_ret;
    tcp_ret = tcp_bind(connection, &net_port.net.ip_addr, 4242 /* bind to some random default port */);
    if(tcp_ret != ERR_OK) {
        RTE_LOG(ERR, APP, "Failed to bind connection: %d\n", tcp_ret);
    }

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

    thread thread_for_ui([](){
      ui_thread();
    });

    struct net_port ports[1] = {
        net_port,
    };
    dispatch_netio_thread(ports, 1, PKT_BURST_SZ);
    thread_for_ui.join();
}

int kbhit()
{
    struct timeval tv;
    fd_set fds;
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds); //STDIN_FILENO is 0
    select(STDIN_FILENO+1, &fds, NULL, NULL, &tv);
    return FD_ISSET(STDIN_FILENO, &fds);
}

void ui_thread() {
    //disable line buffered output, because otherwise our non-blocking I/O will
    //wait for the next line to be entered until it will claim that new characters
    //are available
    setbuf(stdin, NULL);

    bool quit = false;
    while(true) {
        bytes input;
        while(kbhit()) {
            //super ugly, non-blocking console I/O
            char c = fgetc(stdin);
            if(c == EOF) {
                quit = true;
                break;
            }
            input.emplace_back(c);
        }

        if(quit) {
            break;
        }

        {
            if(input.size() > 0) {
                lock_guard<mutex> input_lock_guard(input_mutex);
                input_queue.push(input);
            }
        }

        {
            unique_lock<mutex> output_lock(output_mutex);
            output_condition.wait_for(output_lock, std::chrono::milliseconds(100), []() -> bool {
                return output_queue.empty();
            });

            if(!output_queue.empty()) {
                bytes& output = output_queue.front();
                fwrite(output.data(), 1, output.size(), stdout);
                output_queue.pop();
            }
        }
    }
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
        if (unlikely(n_pkts > pkt_burst_sz))
            continue;

        if (n_pkts == 0)
            continue;

        netif = net_port->netif;
        dispatch_to_ethif(netif, pkts, n_pkts);
    }
    return 0;
}

int
dispatch_netio_thread(struct net_port *ports, int nr_ports, int pkt_burst_sz)
{
    struct rte_mbuf *pkts[pkt_burst_sz];
    int ret = 0;

    while (true) {
        ret = dispatch(ports, nr_ports, pkts, pkt_burst_sz);
        if(ret < 0) {
            break;
        }

        if(connected) {
            ret = dispatch_ui_input();
            if(ret < 0) {
                break;
            }
        }
    }
    return ret;
}

int
dispatch_ui_input()
{
    //check if there is something new in the input buffer
    lock_guard<mutex> lock(input_mutex);

    //send new input text to remote
    if(input_cursor.pos == input_cursor.len()) {
        //if cursor is at the end of the current element,
        //pick a new element from the queue
        if(!input_queue.empty()) {
            bytes& new_input = input_queue.front();
            input_cursor.reset(new_input);
            input_queue.pop();
        }
        else {
            return 0;
        }
    }
    while(!input_cursor.empty()) {
        u16_t available = tcp_sndbuf(connection);
        u16_t send_count = min(available, (u16_t)input_cursor.remaining());

        tcp_write(connection, input_cursor.ptr(), send_count, TCP_WRITE_FLAG_COPY);
        tcp_output(connection);
        input_cursor.consume(send_count);
    }

    return 0;
}



err_t callback_ui_output(void * arg, struct tcp_pcb * tpcb,
                       struct pbuf * p, err_t err)
{
    if(err != ERR_OK) {
        return err;
    }

    unique_lock<mutex> lock(output_mutex);

    bytes data;

    struct pbuf *current_pbuf = p;
    while(current_pbuf != NULL && current_pbuf->len > 0) {
        data.insert(data.end(), (const char*)current_pbuf->payload, ((const char*)current_pbuf->payload) + current_pbuf->len);
        current_pbuf = current_pbuf->next;
    }

    output_queue.emplace(data);

    lock.unlock();
    output_condition.notify_all();

    pbuf_free(p);
    return 0;
}
