#ifndef ETHARP_MASTER_H
#define ETHARP_MASTER_H

#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lwip_dpdk_arp_table;
struct netif;
struct pbuf;

struct lwip_dpdk_master_arp_table {
  struct lwip_dpdk_arp_table* ro_table;
  struct lwip_dpdk_arp_table* rw_table;

  atomic_uint seq;
  pthread_rwlock_t lock;
};

void
lwip_dpdk_etharp_master_table_init(struct lwip_dpdk_master_arp_table* master_table, int socket);
void
lwip_dpdk_etharp_master_table_release(struct lwip_dpdk_master_arp_table* master_table);

void
lwip_dpdk_etharp_master_input(struct pbuf *p, struct netif *netif);

#ifdef __cplusplus
}
#endif

#endif // ETHARP_MASTER_H
