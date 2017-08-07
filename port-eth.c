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

#include <rte_errno.h>
#include <rte_malloc.h>

#include <lwip/ip_addr.h>
#include <lwip/tcp.h>

#include "port-eth.h"
#include "mempool.h"
#include "rss.h"
#include "context_private.h"

#define TCP_LOCAL_PORT_RANGE_START        0xc000
#define TCP_LOCAL_PORT_RANGE_END          0xffff

struct lwip_dpdk_port_eth *
lwip_dpdk_port_eth_create(struct lwip_dpdk_port_eth_params *conf)
{
	struct lwip_dpdk_port_eth *port;
	uint8_t port_id = conf->port_id;
	int ret;

    port = malloc(sizeof(*port));
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "Cannot allocate eth port\n");
		return NULL;
	}

	port->port_id = port_id;
    port->conf = *conf;

    ret = rte_eth_dev_configure(port_id, conf->nb_queues, conf->nb_queues, &conf->eth_conf);
	if (ret < 0) {
		RTE_LOG(ERR, PORT, "Cannot config eth dev: %s\n",
			rte_strerror(-ret));
        free(port);
		return NULL;
	}

	rte_eth_promiscuous_enable(port_id);

  rte_eth_dev_info_get(port_id, &port->eth_dev_info);

  //explicitly set the redirection table
  struct rte_eth_rss_reta_entry64* reta_conf = calloc(port->eth_dev_info.reta_size / RTE_RETA_GROUP_SIZE, sizeof(struct rte_eth_rss_reta_entry64));
  int i;
  for(i = 0; i < port->eth_dev_info.reta_size; ++i) {
    struct rte_eth_rss_reta_entry64* one_reta_conf = &reta_conf[i / RTE_RETA_GROUP_SIZE];
    one_reta_conf->reta[i % RTE_RETA_GROUP_SIZE] = i % conf->nb_queues;
  }

  for(i = 0; i < port->eth_dev_info.reta_size / RTE_RETA_GROUP_SIZE; ++i) {
    struct rte_eth_rss_reta_entry64* one_reta_conf = &reta_conf[i];
    one_reta_conf->mask = 0xFFFFFFFFFFFFFFFFULL;
  }


  rte_eth_dev_rss_reta_update(port_id, reta_conf, port->eth_dev_info.reta_size);

  free(reta_conf);

	return port;
}

int lwip_dpdk_port_eth_start(struct lwip_dpdk_port_eth * port)
{
    int ret = rte_eth_dev_start(port->port_id);
    if (ret < 0) {
        RTE_LOG(ERR, PORT, "Cannot start eth dev: %s\n",
            rte_strerror(-ret));
    }

    return ret;
}

struct lwip_dpdk_queue_eth_select_ip_port_context {
    uint32_t count_queues;
    uint32_t queue_index;
};

void*
lwip_dpdk_queue_eth_select_ip_port_context_create(struct lwip_dpdk_global_context *global_context, struct lwip_dpdk_context *context)
{
    struct lwip_dpdk_queue_eth_select_ip_port_context* select_ip_port_context = rte_zmalloc_socket("lwip_dpdk_queue_eth_select_ip_port_context",
                                                                                                   sizeof(struct lwip_dpdk_queue_eth_select_ip_port_context),
                                                                                                   0,
                                                                                                   rte_lcore_to_socket_id(context->lcore));
    select_ip_port_context->count_queues = global_context->context_count;
    select_ip_port_context->queue_index = context->index;

    return select_ip_port_context;
    //TODO: free the allocated context
}

uint16_t
lwip_dpdk_queue_eth_select_ip_port(struct tcp_pcb ** const* tcp_pcb_lists, uint32_t tcp_pcb_lists_count, const ip_addr_t* src, const ip_addr_t* dst, u16_t dport, void* context)
{
    uint8_t i;
    uint16_t n = 0;
    struct tcp_pcb *pcb;
    uint16_t tcp_port = TCP_LOCAL_PORT_RANGE_START;

    uint32_t cached_value = lwip_dpdk_rss_cached_value_for_rss(src->addr, dst->addr);

    struct lwip_dpdk_queue_eth_select_ip_port_context* select_ip_port_context = (struct lwip_dpdk_queue_eth_select_ip_port_context*)context;
    uint32_t required_queue = select_ip_port_context->queue_index;
    uint32_t count_queues = select_ip_port_context->count_queues;

  again:
    if (tcp_port++ == TCP_LOCAL_PORT_RANGE_END) {
      tcp_port = TCP_LOCAL_PORT_RANGE_START;
    }
    /* Check all PCB lists. */
    for (i = 0; i < tcp_pcb_lists_count; i++) {
      for (pcb = *tcp_pcb_lists[i]; pcb != NULL; pcb = pcb->next) {
        if (pcb->local_port == tcp_port) {
          if (++n > (TCP_LOCAL_PORT_RANGE_END - TCP_LOCAL_PORT_RANGE_START)) {
            return 0;
          }
          goto again;
        }
      }
    }
    /* Check wether packet to this port would land on the correct queue */
    uint32_t hash_value = lwip_dpdk_rss_for_ports(cached_value, tcp_port, dport);
    if(lwip_dpdk_rss_queue_for_hash(hash_value, count_queues) != required_queue) {
        goto again;
    }

    return tcp_port;
}

struct lwip_dpdk_queue_eth*
lwip_dpdk_queue_eth_create(struct lwip_dpdk_context* context, struct lwip_dpdk_port_eth *port, int socket_id, int queue_id)
{
    struct lwip_dpdk_queue_eth* queue;
    int ret;

    queue = rte_zmalloc_socket("QUEUE", sizeof(*queue), RTE_CACHE_LINE_SIZE, socket_id);

    queue->port_id = port->port_id;
    queue->queue_id = queue_id;
    queue->context = context;
    queue->mempool = lwip_dpdk_pktmbuf_pool_get(socket_id);
    queue->eth_port = port;

    ret = rte_eth_rx_queue_setup(port->port_id, queue->queue_id, port->conf.nb_rx_desc, socket_id,
                     &port->conf.rx_conf, queue->mempool);
    if (ret < 0) {
        RTE_LOG(ERR, PORT, "Cannot setup rx queue: %s\n",
            rte_strerror(-ret));
        rte_free(port);
        return NULL;
    }

    ret = rte_eth_tx_queue_setup(port->port_id, queue->queue_id, port->conf.nb_tx_desc, socket_id,
                     &port->conf.tx_conf);
    if (ret < 0) {
        RTE_LOG(ERR, PORT, "Cannot setup tx queue: %s\n",
            rte_strerror(-ret));
        rte_free(port);
        return NULL;
    }

    return queue;
}

int
lwip_dpdk_port_eth_rx_burst(struct lwip_dpdk_queue_eth *lwip_dpdk_port_eth,
		      struct rte_mbuf **pkts, uint32_t n_pkts)
{
	int rx;

    rx = rte_eth_rx_burst(lwip_dpdk_port_eth->port_id, lwip_dpdk_port_eth->queue_id, pkts, n_pkts);
	if (unlikely(rx > n_pkts)) {
                RTE_LOG(ERR, PORT, "Failed to rx eth burst\n");
		return rx;
	}

	return rx;
}

/* buffer ownership and responsivity [tx_burst]
 *   mbuf: transfer the ownership of all mbuf sent successfully to
 *         the underlying device, otherwise free all here
 */
int
lwip_dpdk_port_eth_tx_burst(struct lwip_dpdk_queue_eth *lwip_dpdk_queue_eth,
              struct rte_mbuf **pkts, uint32_t n_pkts)
{
	int tx;

    tx = rte_eth_tx_burst(lwip_dpdk_queue_eth->port_id, lwip_dpdk_queue_eth->queue_id, pkts, n_pkts);

	if (unlikely(tx < n_pkts)) {
		for (; tx < n_pkts; tx++) {
			rte_pktmbuf_free(pkts[tx]);
		}
        }
	return tx;
}
