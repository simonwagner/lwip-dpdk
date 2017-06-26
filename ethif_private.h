#ifndef ETHIF_PRIVATE_H
#define ETHIF_PRIVATE_H

#include <stdint.h>
#include <lwip/ip_addr.h>

#include "ethif.h"

struct lwip_dpdk_global_netif {
    struct netif** context_netifs;
    uint8_t port_id;
    ip_addr_t ipaddr;
    ip_addr_t netmask;
    ip_addr_t gw;

    uint8_t num;
    struct lwip_dpdk_port_eth* port;
};

static inline struct lwip_dpdk_queue_eth* netif_dpdk_ethif(struct netif *netif)
{
    return (struct lwip_dpdk_queue_eth*)netif->state;
}

void lwip_dpdk_global_netif_start(struct lwip_dpdk_global_context* global_context, struct lwip_dpdk_global_netif* global_netif);
void lwip_dpdk_global_netif_release(struct lwip_dpdk_global_context* global_context, struct lwip_dpdk_global_netif* global_netif);
err_t lwip_dpdk_ethif_queue_input(struct netif *netif, struct rte_mbuf *pkt);

#endif // ETHIF_PRIVATE_H
