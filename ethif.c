/*
 *   BSD LICENSE
 *
 *   Copyright(c) 2014 Midokura SARL.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Midokura SARL nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>

#include <lwip/opt.h>
#include <lwip/debug.h>
#include <lwip/mem.h>
#include <lwip/netif.h>
#include <netif/etharp.h>

#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "context.h"
#include "context_private.h"
#include "ethif_private.h"
#include "mempool.h"
#include "tools.h"

#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512

static void lwip_dpdk_netif_add(struct lwip_dpdk_context* context, struct netif* netif, struct lwip_dpdk_port_eth *port, const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw);
static err_t ethif_queue_added_cb(struct netif *netif);

const ip_addr_t* lwip_dpdk_global_netif_get_ipaddr(struct lwip_dpdk_global_netif* global_netif)
{
    return &global_netif->ipaddr;
}

const ip_addr_t* lwip_dpdk_global_netif_get_netmask(struct lwip_dpdk_global_netif* global_netif)
{
    return &global_netif->netmask;
}

const ip_addr_t* lwip_dpdk_global_netif_get_gw(struct lwip_dpdk_global_netif* global_netif)
{
    return &global_netif->gw;
}

uint8_t lwip_dpdk_global_netif_get_port(struct lwip_dpdk_global_netif* global_netif)
{
    return global_netif->port_id;
}

struct lwip_dpdk_global_netif* lwip_dpdk_global_netif_create(struct lwip_dpdk_global_context* global_context, uint8_t port_id, const ip_addr_t* ipaddr, const ip_addr_t* netmask, const ip_addr_t* gw)
{
    assert(global_context->global_netifs_count < LWIP_DPDK_MAX_COUNT_NETIFS);

    struct lwip_dpdk_global_netif* netif = calloc(1, sizeof(struct lwip_dpdk_global_netif));

    netif->port_id = port_id;
    ip_addr_copy(netif->ipaddr, *ipaddr);
    ip_addr_copy(netif->netmask, *netmask);
    ip_addr_copy(netif->gw, *gw);

    netif->num = global_context->global_netifs_count;
    global_context->global_netifs[netif->num] = netif;
    global_context->global_netifs_count += 1;

    return netif;
}

void lwip_dpdk_global_netif_start(struct lwip_dpdk_global_context* global_context, struct lwip_dpdk_global_netif* global_netif)
{
    global_netif->context_netifs = calloc(global_context->context_count, sizeof(struct netif*));

    //create the port for the global network interface
    struct lwip_dpdk_port_eth *port = NULL;
    struct lwip_dpdk_port_eth_params params = {};

    params.port_id = global_netif->port_id;
    params.nb_queues = global_context->context_count;
    params.nb_rx_desc = RTE_TEST_RX_DESC_DEFAULT;
    params.nb_tx_desc = RTE_TEST_TX_DESC_DEFAULT;
    params.eth_conf.link_speeds = ETH_LINK_SPEED_AUTONEG;

    port = lwip_dpdk_port_eth_create(&params);
    if(port == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot alloc eth port\n");
    }

    global_netif->port = port;

    //create a network interface in each context
    int i;
    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];
        unsigned int netif_index = context->netifs_count;

        assert(netif_index < LWIP_DPDK_MAX_COUNT_NETIFS);

        struct netif* netif = &context->netifs[netif_index];
        ++context->netifs_count;

        global_netif->context_netifs[i] = netif;

        lwip_dpdk_netif_add(context, netif, global_netif->port, &global_netif->ipaddr, &global_netif->netmask, &global_netif->gw);
    }

    if(lwip_dpdk_port_eth_start(port) != 0) {
        rte_exit(EXIT_FAILURE, "Cannot start port\n");
    }
}

void lwip_dpdk_global_netif_release(struct lwip_dpdk_global_context* global_context, struct lwip_dpdk_global_netif* global_netif)
{
    int i;
    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];

        context->api->_netif_remove(global_netif->context_netifs[i]);
        free(global_netif->context_netifs[i]);
        global_netif->context_netifs[i] = NULL;
    }
}

static void lwip_dpdk_netif_add(struct lwip_dpdk_context* context, struct netif* netif, struct lwip_dpdk_port_eth *port, const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw)
{
    struct lwip_dpdk_queue_eth *queue = NULL;

    memset(netif, 0, sizeof(struct netif));

    queue = lwip_dpdk_queue_eth_create(context, port, rte_lcore_to_socket_id(context->lcore), context->index);
    if(queue == NULL) {
        rte_exit(EXIT_FAILURE, "Cannot alloc eth queue\n");
    }

    context->api->_netif_add(netif,
          ipaddr,
          netmask,
          gw,
          queue,
          ethif_queue_added_cb,
          context->api->_ethernet_input);

    context->api->_netif_set_link_up(netif);
    context->api->_netif_set_up(netif);
}

/* buffer ownership and responsivity [if_input]
 *   pbuf: transfer the ownership of a newly allocated pbuf to lwip
 *   mbuf: free all here
 */
err_t lwip_dpdk_ethif_queue_input(struct netif *netif, struct rte_mbuf *m)
{
    struct lwip_dpdk_queue_eth *lwip_dpdk_ethif = (struct lwip_dpdk_queue_eth *)netif->state;
	int len = rte_pktmbuf_pkt_len(m);
	char *dat = rte_pktmbuf_mtod(m, char *);
	struct pbuf *p, *q;

    p = lwip_dpdk_ethif->context->api->_pbuf_alloc(PBUF_RAW, len, PBUF_POOL);
	if (p == 0) {
		rte_pktmbuf_free(m);
		return ERR_OK;
	}

	for(q = p; q != NULL; q = q->next) {
		rte_memcpy(q->payload, dat, q->len);
		dat += q->len;
	}
	rte_pktmbuf_free(m);

    return netif->input(p, netif);
}

/* buffer ownership and responsivity [if_output]
 *   pbuf: return all to the caller in lwip
 *   mbuf: transfer the ownership of a newly allocated mbuf to
 *         the underlying port
 */
static err_t low_level_output(struct netif *netif, struct pbuf *p)
{
    struct lwip_dpdk_queue_eth *lwip_dpdk_ethif = (struct lwip_dpdk_queue_eth *)netif->state;
	struct rte_mbuf *m;
	struct pbuf *q;

    m = rte_pktmbuf_alloc(lwip_dpdk_ethif->mempool);
	if (m == NULL)
		return ERR_MEM;

	for(q = p; q != NULL; q = q->next) {
		char *data = rte_pktmbuf_append(m, q->len);
		if (data == NULL) {
			rte_pktmbuf_free(m);
			return ERR_MEM;
		}
		rte_memcpy(data, q->payload, q->len);
	}

    lwip_dpdk_port_eth_tx_burst(lwip_dpdk_ethif, &m, 1);

	return ERR_OK;
}

static err_t ethif_queue_added_cb(struct netif *netif)
{
    struct lwip_dpdk_queue_eth *lwip_dpdk_ethif = (struct lwip_dpdk_queue_eth *)netif->state;

	netif->name[0] = 'e';
	netif->name[1] = 't';
    netif->output = lwip_dpdk_ethif->context->api->_etharp_output;
	netif->linkoutput = low_level_output;
	netif->mtu = 1500;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP;

    //set mac address
    struct ether_addr mac_addr;
    rte_eth_macaddr_get(lwip_dpdk_ethif->eth_port->port_id, &mac_addr);
    memcpy(netif->hwaddr, mac_addr.addr_bytes, ETHER_ADDR_LEN);
    netif->hwaddr_len = ETHER_ADDR_LEN;

	return ERR_OK;
}
