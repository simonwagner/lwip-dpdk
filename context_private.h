#ifndef CONTEXT_PRIVATE_H
#define CONTEXT_PRIVATE_H

#include "context.h"
#include "etharp_private.h"
#include "etharp_master.h"

struct lwip_dpdk_global_context {
    pthread_mutex_t mutex;
    struct lwip_dpdk_context** contexts;
    unsigned int context_count;
    struct lwip_dpdk_global_netif** global_netifs;
    unsigned int global_netifs_count;
    struct lwip_dpdk_master_arp_table master_arp_table;
};

#endif // CONTEXT_PRIVATE_H
