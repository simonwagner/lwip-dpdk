#ifndef ETHARP_PRIVATE_H
#define ETHARP_PRIVATE_H

#include <stdint.h>
#include <stdatomic.h>

#include <lwip/ip4_addr.h>
#include <netif/ethernet.h>

#include "etharp.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lwip_dpdk_context;
struct lwip_dpdk_global_context;

/** ARP states */
enum etharp_state {
  ETHARP_STATE_EMPTY = 0,
  ETHARP_STATE_PENDING,
  ETHARP_STATE_STABLE,
  ETHARP_STATE_STABLE_REREQUESTING_1,
  ETHARP_STATE_STABLE_REREQUESTING_2,
  ETHARP_STATE_STATIC
};

struct lwip_dpdk_arp_entry {
    enum etharp_state state;

    struct eth_addr ethaddr;
    ip4_addr_t ipaddr;

    int ctime;
};

struct lwip_dpdk_arp_queue_entry {
    struct pbuf* q;
    ip4_addr_t ipaddr;
    int netif_index;
    int ctime;
};

#define LWIP_DPDK_ARP_TABLE_SIZE 64
#define LWIP_DPDK_ARP_QUEUE_SIZE 64

struct lwip_dpdk_arp_table {
    struct lwip_dpdk_arp_entry* table;
    int seq;
};

struct lwip_dpdk_arp_queue {
    int queue_length;
    struct lwip_dpdk_arp_queue_entry queue[LWIP_DPDK_ARP_QUEUE_SIZE];
};

err_t
lwip_dpdk_etharp_init(struct lwip_dpdk_global_context *global_context);
err_t
lwip_dpdk_etharp_context_init(struct lwip_dpdk_context* context);
void
lwip_dpdk_etharp_context_release(struct lwip_dpdk_context* context);

void
lwip_dpdk_etharp_table_init(struct lwip_dpdk_arp_table* table, int seq, int socket);

struct eth_addr*
lwip_dpdk_etharp_lookup_ethaddr(struct lwip_dpdk_arp_table* table, ip4_addr_t ipaddr);

void
lwip_dpdk_arp_table_copy(struct lwip_dpdk_arp_table* src, struct lwip_dpdk_arp_table* dst);

void
lwip_dpdk_etharp_tmr(struct lwip_dpdk_context* context);

void
lwip_dpdk_etharp_input(struct pbuf *p, struct netif *netif);
void
lwip_dpdk_etharp_handle_input_for_table(struct lwip_dpdk_context* context, struct pbuf *p, struct netif *netif, struct lwip_dpdk_arp_table* table);
err_t
lwip_dpdk_etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);

#ifdef __cplusplus
}
#endif

#endif // ETHARP_PRIVATE_H
