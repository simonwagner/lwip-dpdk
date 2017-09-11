#include "api.h"
#include "context_private.h"


struct tcp_pcb * lwip_dpdk_tcp_new(struct lwip_dpdk_context* context)
{
  return context->api->tcp_new();
}

lwip_dpdk_err_t lwip_dpdk_tcp_bind(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, const struct ip4_addr *ipaddr, uint16_t port)
{
  return context->api->_tcp_bind(pcb, ipaddr, port);
}

lwip_dpdk_err_t lwip_dpdk_tcp_connect(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, const struct ip4_addr *ipaddr, uint16_t port, lwip_dpdk_tcp_connected_fn connected)
{
  return context->api->_tcp_connect(pcb, ipaddr, port, connected);
}

lwip_dpdk_err_t lwip_dpdk_tcp_write(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, const void *dataptr, uint16_t len, uint8_t apiflags)
{
  return context->api->tcp_write(pcb, dataptr, len, apiflags);
}

lwip_dpdk_err_t lwip_dpdk_tcp_output(struct lwip_dpdk_context* context, struct tcp_pcb *pcb)
{
  return context->api->tcp_output(pcb);
}

void lwip_dpdk_tcp_recved(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, uint16_t len)
{
  context->api->tcp_recved(pcb, len);
}

lwip_dpdk_err_t lwip_dpdk_tcp_close(struct lwip_dpdk_context* context, struct tcp_pcb *pcb)
{
  return context->api->tcp_close(pcb);
}

void lwip_dpdk_tcp_sent(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, lwip_dpdk_tcp_sent_fn sent)
{
  context->api->tcp_sent(pcb, sent);
}

void lwip_dpdk_tcp_arg(struct lwip_dpdk_context* context, struct tcp_pcb * pcb, void * arg)
{
  context->api->tcp_arg(pcb, arg);
}

void lwip_dpdk_tcp_err(struct lwip_dpdk_context* context, struct tcp_pcb * pcb, void (* err)(void * arg, lwip_dpdk_err_t err))
{
  context->api->tcp_err(pcb, err);
}

void lwip_dpdk_tcp_recv(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, lwip_dpdk_tcp_recv_fn recv)
{
  context->api->tcp_recv(pcb, recv);
}

void lwip_dpdk_sys_check_timeouts(struct lwip_dpdk_context* context)
{
  context->api->sys_check_timeouts();
}
