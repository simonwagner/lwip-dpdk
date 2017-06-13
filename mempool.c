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

#include "main.h"
#include "mempool.h"

#define LWIP_DPDK_MAX_SOCKETS 16

struct rte_mempool* pktmbuf_pools[LWIP_DPDK_MAX_SOCKETS] = {};
const char* pkt_mbuf_pool_names[LWIP_DPDK_MAX_SOCKETS] = {
    "pktmbuf_pool_socket_00",
    "pktmbuf_pool_socket_01",
    "pktmbuf_pool_socket_02",
    "pktmbuf_pool_socket_03",
    "pktmbuf_pool_socket_04",
    "pktmbuf_pool_socket_05",
    "pktmbuf_pool_socket_06",
    "pktmbuf_pool_socket_07",
    "pktmbuf_pool_socket_08",
    "pktmbuf_pool_socket_09",
    "pktmbuf_pool_socket_10",
    "pktmbuf_pool_socket_11",
    "pktmbuf_pool_socket_12",
    "pktmbuf_pool_socket_13",
    "pktmbuf_pool_socket_14",
    "pktmbuf_pool_socket_15",
};

int
lwip_dpdk_pktmbuf_pool_create_all(int max_socket_id)
{
    if(max_socket_id >= LWIP_DPDK_MAX_SOCKETS) {
        rte_panic("max_socket_id is too large, you are only allowed a maximum of %d sockets", LWIP_DPDK_MAX_SOCKETS);
        return -1;
    }

    int i;
    for(i = 0; i <= max_socket_id; i++) {
        struct rte_mempool* pktmbuf_pool;

        pktmbuf_pool = rte_mempool_create(
            pkt_mbuf_pool_names[i], NB_MBUF, MBUF_SZ, MEMPOOL_CACHE_SZ,
            sizeof(struct rte_pktmbuf_pool_private),
            rte_pktmbuf_pool_init, NULL, rte_pktmbuf_init, NULL,
            i, 0);

        if (!pktmbuf_pool) {
            rte_panic("Cannot create pktmbuf pool\n");
            return -1;
        }

        pktmbuf_pools[i] = pktmbuf_pool;
    }

    return 0;
}

struct rte_mempool*
lwip_dpdk_pktmbuf_pool_get(int socket_id)
{
    if(socket_id >= LWIP_DPDK_MAX_SOCKETS) {
        rte_panic("socket_id is too large, you are only allowed a maximum of %d sockets", LWIP_DPDK_MAX_SOCKETS);
        return NULL;
    }

    return pktmbuf_pools[socket_id];
}
