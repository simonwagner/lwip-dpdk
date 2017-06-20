#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdint.h>

#include <lwip/ip_addr.h>
#include <lwip/err.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_DPDK_MAX_COUNT_CONTEXTS 16


struct netif;
struct tcp_pcb;


struct lwip_dpdk_lwip_api {
    void* handle;

    struct netif* netif_list;

    //function pointers
    //- fp generic
    void (*_lwip_init)(void);

    //- fp netif
    struct netif *(*_netif_add)(struct netif *netif,
    #if LWIP_IPV4
                            const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
    #endif /* LWIP_IPV4 */
                            void *state, netif_init_fn init, netif_input_fn input);
    void (*_netif_set_up)(struct netif *netif);
    void (*_netif_set_link_up)(struct netif *netif);
    //- fp ethernet
    err_t (*_ethernet_input)(struct pbuf *p, struct netif *inp);
    err_t (*_etharp_output)(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);
    //- fp tcp
    struct tcp_pcb * (*tcp_new)(void);
    err_t            (*_tcp_bind)    (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                  u16_t port);
    err_t            (*_tcp_connect) (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                  u16_t port, tcp_connected_fn connected);
    err_t            (*tcp_write)   (struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                                  u8_t apiflags);
    err_t            (*tcp_output)  (struct tcp_pcb *pcb);
    void             (*tcp_recved)(struct tcp_pcb *pcb, u16_t len);
    err_t            (*tcp_close)(struct tcp_pcb *pcb);
    void             (*tcp_sent)(struct tcp_pcb *pcb, tcp_sent_fn sent);

    //- fp tcp callback
    void             (*tcp_recv)    (struct tcp_pcb *pcb, tcp_recv_fn recv);
    //- fp timers
    void (*sys_check_timeouts)(void);
    //- fp memory
    struct pbuf * (*_pbuf_alloc)(pbuf_layer layer, u16_t length, pbuf_type type);
    //- fp utility
    char *(*ip4addr_ntoa)(const ip4_addr_t *addr);


};

struct lwip_dpdk_context {
    unsigned lcore;
    struct lwip_dpdk_lwip_api* api;
};

struct lwip_dpdk_global_context;

struct lwip_dpdk_global_context* lwip_dpdk_init();
void lwip_dpdk_close(struct lwip_dpdk_global_context* global_context);

struct lwip_dpdk_context* lwip_dpdk_context_create(struct lwip_dpdk_global_context* global_context, uint8_t lcore, struct lwip_dpdk_context* parent_context);

#ifdef __cplusplus
}
#endif

#endif // CONTEXT_H
