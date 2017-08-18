#include "etharp_slave.h"

#include <lwip/opt.h>
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/dhcp.h>
#include <lwip/autoip.h>
#include <lwip/pbuf.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/ip4.h>
#include <netif/ethernet.h>
#include <lwip/prot/etharp.h>

#include "etharp.h"
#include "ethif_private.h"
#include "context_private.h"

void
lwip_dpdk_etharp_slave_input(struct pbuf *p, struct netif *netif)
{
    struct lwip_dpdk_queue_eth* lwip_dpdk_queue;
    struct lwip_dpdk_context* context;

    LWIP_ASSERT("netif != NULL", netif != NULL);

    lwip_dpdk_queue = netif_dpdk_ethif(netif);
    context = lwip_dpdk_queue->context;

    /* free ARP packet */
    context->api->_pbuf_free(p);
    //well this should not happen, the ARP slave should not receive any ARP packages
    LWIP_ERROR("received packet on ARP slave - this should not happen", 1, return;);
}
