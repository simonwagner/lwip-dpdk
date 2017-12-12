#ifndef LWIP_DPDK_API_H
#define LWIP_DPDK_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tcp_pcb;
struct lwip_dpdk_context;
struct ip4_addr;
struct pbuf;

typedef int8_t lwip_dpdk_err_t;
typedef lwip_dpdk_err_t (*lwip_dpdk_tcp_connected_fn)(void *arg, struct tcp_pcb *tpcb, lwip_dpdk_err_t err);
typedef lwip_dpdk_err_t (*lwip_dpdk_tcp_sent_fn)(void *arg, struct tcp_pcb *tpcb, uint16_t len);
typedef lwip_dpdk_err_t (*lwip_dpdk_tcp_recv_fn)(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, lwip_dpdk_err_t err);

struct tcp_pcb * lwip_dpdk_tcp_new(struct lwip_dpdk_context* context);
lwip_dpdk_err_t lwip_dpdk_tcp_bind(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, uint32_t ipaddr, uint16_t port);
lwip_dpdk_err_t lwip_dpdk_tcp_connect(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, uint32_t ipaddr, uint16_t port, lwip_dpdk_tcp_connected_fn connected);
lwip_dpdk_err_t lwip_dpdk_tcp_write(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, const void *dataptr, uint16_t len, uint8_t apiflags);
lwip_dpdk_err_t lwip_dpdk_tcp_output(struct lwip_dpdk_context* context, struct tcp_pcb *pcb);
void lwip_dpdk_tcp_recved(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, uint16_t len);
lwip_dpdk_err_t lwip_dpdk_tcp_close(struct lwip_dpdk_context* context, struct tcp_pcb *pcb);
void lwip_dpdk_tcp_sent(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, lwip_dpdk_tcp_sent_fn sent);
void lwip_dpdk_tcp_arg(struct lwip_dpdk_context* context, struct tcp_pcb * pcb, void * arg);
void lwip_dpdk_tcp_err(struct lwip_dpdk_context* context, struct tcp_pcb * pcb, void (*err)(void *, lwip_dpdk_err_t));
void lwip_dpdk_tcp_recv(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, lwip_dpdk_tcp_recv_fn recv);
uint32_t lwip_dpdk_tcp_sndbuf(struct tcp_pcb *pcb);
int lwip_dpdk_ip4addr_aton(const char *cp, struct ip4_addr *addr);

#ifdef __cplusplus
}
#endif

#endif // LWIP_DPDK_API_H
