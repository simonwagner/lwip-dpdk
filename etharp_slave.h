#ifndef ETHARP_SLAVE_H
#define ETHARP_SLAVE_H

struct pbuf;
struct netif;

void
lwip_dpdk_etharp_slave_input(struct pbuf *p, struct netif *netif);

#endif // ETHARP_SLAVE_H
