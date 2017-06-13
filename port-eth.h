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

typedef int (*lwip_dpdk_port_op_rx_burst)
    (struct lwip_dpdk_queue_eth *queue, struct rte_mbuf **pkts, uint32_t n_pkts);
typedef int (*lwip_dpdk_port_op_tx_burst)
    (struct lwip_dpdk_queue_eth *queue, struct rte_mbuf **pkts, uint32_t n_pkts);

struct lwip_dpdk_port_ops {
    lwip_dpdk_port_op_rx_burst	rx_burst;
    lwip_dpdk_port_op_tx_burst	tx_burst;
};

struct lwip_dpdk_port_eth_params {
	uint8_t			 port_id;
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
    struct lwip_dpdk_port_ops	     ops;
    struct rte_mempool	*mempool;
    struct lwip_dpdk_port_eth	*eth_port;
};

struct lwip_dpdk_port_eth * lwip_dpdk_port_eth_create
    (struct lwip_dpdk_port_eth_params *conf);
int lwip_dpdk_port_eth_start(struct lwip_dpdk_port_eth * port); /* only call this after you have setup the queues */
struct lwip_dpdk_queue_eth* lwip_dpdk_queue_eth_create
    (struct lwip_dpdk_port_eth *port, int socket_id, int queue_id);
int lwip_dpdk_port_eth_tx_burst
    (struct lwip_dpdk_queue_eth *lwip_dpdk_queue_eth, struct rte_mbuf **pkts, uint32_t n_pkts);

#ifdef __cplusplus
}
#endif

#endif
