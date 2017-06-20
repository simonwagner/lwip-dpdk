#define _GNU_SOURCE

#include <stdlib.h>
#include <dlfcn.h>
#include <pthread.h>
#include <errno.h>

#include "context.h"

#define LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, symbol, name) do { api->symbol = dlsym(api->handle, #name); if(api->symbol == NULL) { return -1; } } while(0)
#define LWIP_DPDK_LOAD_SYMBOL(api, name) LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, name, name)
#define LWIP_DPDK_LOAD_PRIVATE_SYMBOL(api, name) LWIP_DPDK_LOAD_SYMBOL_BY_NAME(api, _ ## name, name)

struct lwip_dpdk_context_list_element {
    struct lwip_dpdk_context* value;
    struct lwip_dpdk_context_list_element* next;
};

static struct lwip_dpdk_context_list_element* context_list_head;
static pthread_mutex_t context_list_mutex;

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

void lwip_dpdk_init()
{
    pthread_mutex_init(&context_list_mutex, NULL);
}

static int lwip_dpdk_context_clone_config_from(struct lwip_dpdk_context* context, struct lwip_dpdk_context* parent_context)
{
    return 0;
}

struct lwip_dpdk_context* lwip_dpdk_context_create(uint8_t lcore, struct lwip_dpdk_context *parent_context)
{
    struct lwip_dpdk_context* context = calloc(1, sizeof(struct lwip_dpdk_context));
    struct lwip_dpdk_lwip_api* api = calloc(1, sizeof(struct lwip_dpdk_lwip_api));

    if(lwip_dpdk_init_api(api, "./liblwip.so") != 0) {
        free(context);
        free(api);
        return NULL;
    }

    context->api = api;
    context->lcore = lcore;

    if(parent_context != NULL) {
        if(lwip_dpdk_context_clone_config_from(context, parent_context) != 0) {
            free(context);
            free(api);
            return NULL;
        }
    }

    context->api->_lwip_init();

    //insert context into context list
    pthread_mutex_lock(&context_list_mutex);

    struct lwip_dpdk_context_list_element* list_element = calloc(1, sizeof(struct lwip_dpdk_context_list_element));
    list_element->value = context;
    struct lwip_dpdk_context_list_element** tail_address = &context_list_head;
    while(*tail_address != NULL) {
        tail_address = &((*tail_address)->next);
    }
    *tail_address = list_element;

    pthread_mutex_unlock(&context_list_mutex);

    return context;
}

void lwip_dpdk_context_release_all()
{
    pthread_mutex_lock(&context_list_mutex);

    struct lwip_dpdk_context_list_element* current_element = context_list_head;
    context_list_head = NULL;

    while(current_element != NULL) {
        struct lwip_dpdk_context* context = current_element->value;

        dlclose(context->api->handle);
        free(context->api);
        free(context);

        struct lwip_dpdk_context_list_element* prev_element = current_element;
        current_element = prev_element->next;
        free(prev_element);
    }

    pthread_mutex_unlock(&context_list_mutex);
}
