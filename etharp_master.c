#include "etharp_master.h"
#include "etharp_private.h"

#include <rte_malloc.h>

#include <lwip/opt.h>
#include <lwip/stats.h>
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
lwip_dpdk_etharp_master_table_init(struct lwip_dpdk_master_arp_table* master_table, int socket)
{
  memset(master_table, 0, sizeof(struct lwip_dpdk_master_arp_table));

  pthread_rwlock_init(&master_table->lock, NULL);

  master_table->ro_table = rte_zmalloc_socket("lwip_dpdk_arp_table",
                                              sizeof(struct lwip_dpdk_arp_table),
                                              RTE_CACHE_LINE_SIZE,
                                              socket);
  lwip_dpdk_etharp_table_init(master_table->ro_table, 0, socket);

  master_table->rw_table = rte_zmalloc_socket("lwip_dpdk_arp_table",
                                              sizeof(struct lwip_dpdk_arp_table),
                                              RTE_CACHE_LINE_SIZE,
                                              socket);
  lwip_dpdk_etharp_table_init(master_table->rw_table, 0, socket);
}

void
lwip_dpdk_etharp_master_table_release(struct lwip_dpdk_master_arp_table* master_table)
{
  rte_free(master_table->ro_table);
  rte_free(master_table->rw_table);
}

static void
lwip_dpdk_etharp_master_table_publish_changes(struct lwip_dpdk_master_arp_table* master_table)
{
  if(master_table->rw_table->seq != master_table->seq) {
    pthread_rwlock_wrlock(&master_table->lock);

    //overwrite the old entries in ro_table with the
    //new entries in rw_table
    lwip_dpdk_arp_table_copy(master_table->rw_table, master_table->ro_table);
    master_table->ro_table->seq = master_table->rw_table->seq;

    master_table->seq = master_table->ro_table->seq;

    pthread_rwlock_unlock(&master_table->lock);
  }
}

void
lwip_dpdk_etharp_master_input(struct pbuf *p, struct netif *netif)
{
  LWIP_ERROR("netif != NULL", (netif != NULL), return;);

  struct lwip_dpdk_queue_eth* lwip_dpdk_queue;
  struct lwip_dpdk_context* context;

  lwip_dpdk_queue = netif_dpdk_ethif(netif);
  context = lwip_dpdk_queue->context;

  lwip_dpdk_etharp_handle_input_for_table(context, p, netif, context->global_arp_table->rw_table);

  lwip_dpdk_etharp_master_table_publish_changes(context->global_arp_table);
}
