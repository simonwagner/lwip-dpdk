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
#ifndef _PORT_ETH_H_
#define _PORT_ETH_H_

#include <rte_ethdev.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lwip_dpdk_queue_eth;
struct lwip_dpdk_context;
struct lwip_dpdk_global_context;

struct lwip_dpdk_port_eth_params {
	uint8_t			 port_id;
    uint16_t         nb_queues;
	uint16_t		 nb_rx_desc;
	uint16_t		 nb_tx_desc;
	struct rte_eth_conf	 eth_conf;
	struct rte_eth_rxconf	 rx_conf;
	struct rte_eth_txconf	 tx_conf;
};

struct lwip_dpdk_port_eth {
    uint8_t			         port_id;
    struct lwip_dpdk_port_eth_params conf;
	struct rte_eth_dev_info	 eth_dev_info;
};

struct lwip_dpdk_queue_eth {
    uint8_t port_id; //copy of eth_port->port_id for efficiency
    uint8_t queue_id;
    uint8_t socket_id;
    struct rte_mempool	*mempool;
    struct lwip_dpdk_context *context;
    struct lwip_dpdk_port_eth	*eth_port;
};

struct lwip_dpdk_port_eth * lwip_dpdk_port_eth_create
    (struct lwip_dpdk_port_eth_params *conf);
int lwip_dpdk_port_eth_start(struct lwip_dpdk_port_eth * port); /* only call this after you have setup the queues */
struct lwip_dpdk_queue_eth* lwip_dpdk_queue_eth_create
    (struct lwip_dpdk_context* context, struct lwip_dpdk_port_eth *port, int socket_id, int queue_id);
int lwip_dpdk_port_eth_tx_burst
    (struct lwip_dpdk_queue_eth *lwip_dpdk_queue_eth, struct rte_mbuf **pkts, uint32_t n_pkts);
int
lwip_dpdk_port_eth_rx_burst(struct lwip_dpdk_queue_eth *lwip_dpdk_port_eth,
              struct rte_mbuf **pkts, uint32_t n_pkts);
uint16_t
lwip_dpdk_queue_eth_select_ip_port(struct tcp_pcb ** const* tcp_pcb_lists, uint32_t tcp_pcb_lists_count, const ip_addr_t* src, const ip_addr_t* dst, u16_t dport, void* context);
void*
lwip_dpdk_queue_eth_select_ip_port_context_create(struct lwip_dpdk_global_context *global_context, struct lwip_dpdk_context *context);

#ifdef __cplusplus
}
#endif

#endif
