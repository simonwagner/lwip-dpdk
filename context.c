#define _GNU_SOURCE

#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

#include <link.h>

#include "context_private.h"
#include "mempool.h"
#include "ethif_private.h"
#include "rss.h"

#define LWIP_DPDK_PKT_BURST_SZ 512

#define LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, symbol, name) do { api->symbol = dlsym(api->handle, #name); if(api->symbol == NULL) { return -1; } } while(0)
#define LWIP_DPDK_LOAD_SYMBOL(api, name) LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, name, name)
#define LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, name) LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, _ ## name, name)

struct netif;

const ip_addr_t lwip_dpdk_ip_addr_any = IPADDR4_INIT(IPADDR_ANY);

static int lwip_dpdk_init_api(struct lwip_dpdk_lwip_api* api, const char* lwip_library_path)
{
    api->handle = dlmopen(LM_ID_NEWLM, lwip_library_path, RTLD_NOW | RTLD_LOCAL);
    if(api->handle == NULL) {
        return -ENOENT;
    }

    struct link_map* link_map;
    dlinfo(api->handle, RTLD_DI_LINKMAP, &link_map);

    printf("lwip API has been loaded to address %p\n", link_map->l_addr);

    //fp generic
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, lwip_init);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, tcp_set_new_port_fn);

    //fp netif
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_add);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_set_up);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_set_link_up);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_remove);

    //fp ethernet
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, ethernet_input);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, etharp_output);

    //fp tcp
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_new);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, tcp_bind);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, tcp_connect);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_write);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_output);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_recved);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_close);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_arg);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_err);

    //fp tcp callback
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_recv);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_sent);

    //fp timeout
    LWIP_DPDK_LOAD_SYMBOL(api, sys_check_timeouts);

    //fp memory
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, pbuf_alloc);

    //fp utility
    LWIP_DPDK_LOAD_SYMBOL(api, ip4addr_ntoa);
    LWIP_DPDK_LOAD_SYMBOL(api, lwip_htons);
    LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, lwip_ntohs, lwip_htons);

    return 0;
}

struct lwip_dpdk_global_context* lwip_dpdk_init()
{
    struct lwip_dpdk_global_context* global_context = calloc(1, sizeof(struct lwip_dpdk_global_context));

    pthread_mutex_init(&global_context->mutex, NULL);

    global_context->contexts = calloc(LWIP_DPDK_MAX_COUNT_CONTEXTS, sizeof(struct lwip_dpdk_context*));
    global_context->global_netifs = calloc(LWIP_DPDK_MAX_COUNT_NETIFS, sizeof(struct lwip_dpdk_global_netif*));

    lwip_dpdk_rss_init();

    return global_context;
}

struct lwip_dpdk_context* lwip_dpdk_context_create(struct lwip_dpdk_global_context* global_context, uint8_t lcore)
{
    struct lwip_dpdk_context* context = calloc(1, sizeof(struct lwip_dpdk_context));
    struct lwip_dpdk_lwip_api* api = calloc(1, sizeof(struct lwip_dpdk_lwip_api));

    if(lwip_dpdk_init_api(api, "./liblwip.so") != 0) {
        goto fail;
    }

    context->api = api;
    context->lcore = lcore;

    context->api->_lwip_init();

    //insert context into context list
    pthread_mutex_lock(&global_context->mutex);

    if(global_context->context_count >= LWIP_DPDK_MAX_COUNT_CONTEXTS) {
        goto fail;
    }
    size_t index = global_context->context_count;
    ++global_context->context_count;
    global_context->contexts[index] = context;
    context->index = index;

    pthread_mutex_unlock(&global_context->mutex);

    return context;

fail:
    free(context);
    free(api);
    return NULL;
}

static void lwip_dpdk_context_release(struct lwip_dpdk_context* context)
{
    dlclose(context->api->handle);
    free(context->api);
    free(context);
}



int lwip_dpdk_start(struct lwip_dpdk_global_context* global_context)
{
    int i;

    //allocate memory buffer pools for all sockets
    unsigned int max_socket = 0;
    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];
        unsigned int context_socket = rte_lcore_to_socket_id(context->lcore);
        max_socket = max_socket < context_socket ? context_socket : max_socket;
    }

    lwip_dpdk_pktmbuf_pool_create_all(max_socket);

    //allocate memory for network interfaces in contexts
    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];
        context->netifs_count = 0;
        context->netifs = calloc(LWIP_DPDK_MAX_COUNT_NETIFS, sizeof(struct netif));
    }

    //setup network interfaces
    for(i = 0; i < global_context->global_netifs_count; ++i) {
        struct lwip_dpdk_global_netif* global_netif = global_context->global_netifs[i];

        lwip_dpdk_global_netif_start(global_context, global_netif);
    }
    //set the function for selecting the correct source port
    //so that RSS works
    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];
        context->api->_tcp_set_new_port_fn(lwip_dpdk_queue_eth_select_ip_port,
                                           lwip_dpdk_queue_eth_select_ip_port_context_create(global_context, context));
    }


    return 0;
}

void lwip_dpdk_close(struct lwip_dpdk_global_context* global_context)
{
    pthread_mutex_lock(&global_context->mutex);

    int i;

    for(i = 0; i < global_context->global_netifs_count; ++i) {
        struct lwip_dpdk_global_netif* netif = global_context->global_netifs[i];

        lwip_dpdk_global_netif_release(global_context, netif);
    }
    free(global_context->global_netifs);

    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];

        lwip_dpdk_context_release(context);
    }
    free(global_context->contexts);

    //reset global_context
    global_context->contexts = NULL;
    global_context->context_count = 0;
    global_context->global_netifs = NULL;
    global_context->global_netifs_count = 0;

    pthread_mutex_unlock(&global_context->mutex);

    free(global_context);
}

int lwip_dpdk_context_dispatch_input(struct lwip_dpdk_context* context)
{
    int i, j;
    struct rte_mbuf *pkts[LWIP_DPDK_PKT_BURST_SZ];

    context->api->sys_check_timeouts(); //TODO: this should be moved to its own method

    for(i = 0; i < context->netifs_count; ++i) {
        struct netif* netif = &context->netifs[i];
        uint32_t n_pkts;

        do {
            struct lwip_dpdk_queue_eth* lwip_dpdk_queue = netif_dpdk_ethif(netif);

            n_pkts = lwip_dpdk_port_eth_rx_burst(lwip_dpdk_queue, pkts, LWIP_DPDK_PKT_BURST_SZ);

            for (j = 0; j < n_pkts; j++) {
                lwip_dpdk_ethif_queue_input(netif, pkts[i]);
            }

        } while(unlikely(n_pkts > LWIP_DPDK_PKT_BURST_SZ));
    }

    return 0;
}
