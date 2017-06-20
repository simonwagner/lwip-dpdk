#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>

#include "context.h"

#define LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, symbol, name) do { api->symbol = dlsym(api->handle, #name); if(api->symbol == NULL) { return -1; } } while(0)
#define LWIP_DPDK_LOAD_SYMBOL(api, name) LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, name, name)
#define LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, name) LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, _ ## name, name)

struct lwip_dpdk_global_context {
    pthread_mutex_t mutex;
    struct lwip_dpdk_context** contexts;
    int context_count;
};

static int lwip_dpdk_init_api(struct lwip_dpdk_lwip_api* api, const char* lwip_library_path)
{
    api->handle = dlmopen(LM_ID_NEWLM, lwip_library_path, RTLD_NOW | RTLD_LOCAL);
    if(api->handle == NULL) {
        return -ENOENT;
    }

    //fp generic
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, lwip_init);

    //fp netif
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_add);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_set_up);
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, netif_set_link_up);

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
    //fp tcp callback
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_recv);
    LWIP_DPDK_LOAD_SYMBOL(api, tcp_sent);

    //fp timeout
    LWIP_DPDK_LOAD_SYMBOL(api, sys_check_timeouts);

    //fp memory
    LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, pbuf_alloc);

    //fp utility
    LWIP_DPDK_LOAD_SYMBOL(api, ip4addr_ntoa);

    return 0;
}

struct lwip_dpdk_global_context* lwip_dpdk_init()
{
    struct lwip_dpdk_global_context* global_context = calloc(1, sizeof(struct lwip_dpdk_global_context));

    pthread_mutex_init(&global_context->mutex, NULL);

    global_context->contexts = calloc(LWIP_DPDK_MAX_COUNT_CONTEXTS, sizeof(struct lwip_dpdk_context*));

    return global_context;
}

static int lwip_dpdk_context_clone_config_from(struct lwip_dpdk_context* context, struct lwip_dpdk_context* parent_context)
{
    return 0;
}

struct lwip_dpdk_context* lwip_dpdk_context_create(struct lwip_dpdk_global_context* global_context, uint8_t lcore, struct lwip_dpdk_context *parent_context)
{
    struct lwip_dpdk_context* context = calloc(1, sizeof(struct lwip_dpdk_context));
    struct lwip_dpdk_lwip_api* api = calloc(1, sizeof(struct lwip_dpdk_lwip_api));

    if(lwip_dpdk_init_api(api, "./liblwip.so") != 0) {
        goto fail;
    }

    context->api = api;
    context->lcore = lcore;

    if(parent_context != NULL) {
        if(lwip_dpdk_context_clone_config_from(context, parent_context) != 0) {
            goto fail;
        }
    }

    context->api->_lwip_init();

    //insert context into context list
    pthread_mutex_lock(&global_context->mutex);

    if(global_context->context_count >= LWIP_DPDK_MAX_COUNT_CONTEXTS) {
        goto fail;
    }
    size_t index = global_context->context_count;
    global_context->contexts[index] = context;

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

void lwip_dpdk_close(struct lwip_dpdk_global_context* global_context)
{
    pthread_mutex_lock(&global_context->mutex);

    int i;
    for(i = 0; i < global_context->context_count; ++i) {
        struct lwip_dpdk_context* context = global_context->contexts[i];

        lwip_dpdk_context_release(context);
    }
    free(global_context->contexts);

    //reset global_context
    global_context->contexts = NULL;
    global_context->context_count = 0;
    pthread_mutex_unlock(&global_context->mutex);

    free(global_context);
}
