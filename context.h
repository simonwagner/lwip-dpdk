#ifndef CONTEXT_H
#define CONTEXT_H

#include <stdint.h>

#include <lwip/ip_addr.h>
#include <lwip/err.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <netif/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LWIP_DPDK_MAX_COUNT_NETIFS 9
#define LWIP_DPDK_MAX_COUNT_CONTEXTS 16


struct netif;
struct tcp_pcb;

extern const ip_addr_t lwip_dpdk_ip_addr_any;

struct lwip_dpdk_lwip_api {
    void* handle;

    struct netif* netif_list;

    //function pointers
    //- fp generic
    void (*_lwip_init)(void);
    void (*_tcp_set_new_port_fn)(tcp_new_port_fn fn, void* context);

    //- fp netif
    struct netif *(*_netif_add)(struct netif *netif,
    #if LWIP_IPV4
                            const ip4_addr_t *ipaddr, const ip4_addr_t *netmask, const ip4_addr_t *gw,
    #endif /* LWIP_IPV4 */
                            void *state, netif_init_fn init, netif_input_fn input);
    void (*_netif_set_up)(struct netif *netif);
    void (*_netif_set_link_up)(struct netif *netif);
    void (*_netif_remove)(struct netif *netif);
    //- fp ethernet
    err_t (*_ethernet_input)(struct pbuf *p, struct netif *inp);
    err_t (*_ethernet_output)(struct netif* netif, struct pbuf* p, const struct eth_addr* src, const struct eth_addr* dst, u16_t eth_type);
    err_t (*_etharp_output)(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr);
    //- fp tcp
    struct tcp_pcb * (*tcp_new)(void);
    err_t            (*tcp_bind)    (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                  u16_t port);
    err_t            (*tcp_connect) (struct tcp_pcb *pcb, const ip_addr_t *ipaddr,
                                  u16_t port, tcp_connected_fn connected);
    err_t            (*tcp_write)   (struct tcp_pcb *pcb, const void *dataptr, u16_t len,
                                  u8_t apiflags);
    err_t            (*tcp_output)  (struct tcp_pcb *pcb);
    void             (*tcp_recved)(struct tcp_pcb *pcb, u16_t len);
    err_t            (*tcp_close)(struct tcp_pcb *pcb);
    void             (*tcp_sent)(struct tcp_pcb *pcb, tcp_sent_fn sent);
    void             (*tcp_arg)(struct tcp_pcb * pcb, void * arg);
    void             (*tcp_err)(struct tcp_pcb * pcb, void (* err)(void * arg, err_t err));

    //- fp tcp callback
    void             (*tcp_recv)    (struct tcp_pcb *pcb, tcp_recv_fn recv);
    //- fp timers
    void (*_sys_check_timeouts)(void);
    //- fp memory
    struct pbuf * (*_pbuf_alloc)(pbuf_layer layer, u16_t length, pbuf_type type);
    u8_t (*_pbuf_free)(struct pbuf *p);
    //- fp utility
    char *(*ip4addr_ntoa)(const ip4_addr_t *addr);
    u16_t (*lwip_ntohs)(u16_t s);
    u16_t (*lwip_htons)(u16_t s);


};

struct lwip_dpdk_arp_table;
struct lwip_dpdk_arp_queue;

struct lwip_dpdk_context {
    unsigned lcore;
    struct lwip_dpdk_lwip_api* api;
    struct netif* netifs;
    unsigned int netifs_count;
    unsigned int index;
    struct lwip_dpdk_arp_table* arp_table;
    struct lwip_dpdk_arp_queue* arp_queue;
    struct lwip_dpdk_master_arp_table* global_arp_table;
};

struct lwip_dpdk_global_context;
struct lwip_dpdk_global_netif;

struct lwip_dpdk_global_context* lwip_dpdk_init();
int lwip_dpdk_start(struct lwip_dpdk_global_context* global_context);
void lwip_dpdk_close(struct lwip_dpdk_global_context* global_context);

struct lwip_dpdk_context* lwip_dpdk_context_create(struct lwip_dpdk_global_context* global_context, uint8_t lcore);
int lwip_dpdk_context_dispatch_input(struct lwip_dpdk_context* context);
void lwip_dpdk_context_handle_timers(struct lwip_dpdk_context* context);

#ifdef __cplusplus
}
#endif

#endif // CONTEXT_H
