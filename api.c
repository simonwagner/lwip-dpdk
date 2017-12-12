#include "api.h"

#include <ctype.h>
#include <assert.h>

#include <lwip/ip_addr.h>

#include "context_private.h"


struct tcp_pcb * lwip_dpdk_tcp_new(struct lwip_dpdk_context* context)
{
  return context->api->tcp_new();
}

lwip_dpdk_err_t lwip_dpdk_tcp_bind(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, uint32_t ipaddr, uint16_t port)
{
  ip_addr_t _ipaddr = IPADDR4_INIT(ipaddr);
  return context->api->tcp_bind(pcb, &_ipaddr, port);
}

lwip_dpdk_err_t lwip_dpdk_tcp_connect(struct lwip_dpdk_context* context, struct tcp_pcb *pcb, uint32_t ipaddr, uint16_t port, lwip_dpdk_tcp_connected_fn connected)
{
  ip_addr_t _ipaddr = IPADDR4_INIT(ipaddr);
  return context->api->tcp_connect(pcb, &_ipaddr, port, connected);
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

uint32_t lwip_dpdk_tcp_sndbuf(struct tcp_pcb *pcb)
{
    return TCPWND16((pcb)->snd_buf);
}

int lwip_dpdk_ip4addr_aton(const char *cp, struct ip4_addr *addr)
{
    uint32_t val;
    uint8_t base;
    char c;
    uint32_t parts[4];
    uint32_t *pp = parts;

    c = *cp;
    for (;;) {
      /*
       * Collect number up to ``.''.
       * Values are specified as for C:
       * 0x=hex, 0=octal, 1-9=decimal.
       */
      if (!isdigit(c)) {
        return 0;
      }
      val = 0;
      base = 10;
      if (c == '0') {
        c = *++cp;
        if (c == 'x' || c == 'X') {
          base = 16;
          c = *++cp;
        } else {
          base = 8;
        }
      }
      for (;;) {
        if (isdigit(c)) {
          val = (val * base) + (int)(c - '0');
          c = *++cp;
        } else if (base == 16 && isxdigit(c)) {
          val = (val << 4) | (int)(c + 10 - (islower(c) ? 'a' : 'A'));
          c = *++cp;
        } else {
          break;
        }
      }
      if (c == '.') {
        /*
         * Internet format:
         *  a.b.c.d
         *  a.b.c   (with c treated as 16 bits)
         *  a.b (with b treated as 24 bits)
         */
        if (pp >= parts + 3) {
          return 0;
        }
        *pp++ = val;
        c = *++cp;
      } else {
        break;
      }
    }
    /*
     * Check for trailing characters.
     */
    if (c != '\0' && !isspace(c)) {
      return 0;
    }
    /*
     * Concoct the address according to
     * the number of parts specified.
     */
    switch (pp - parts + 1) {

    case 0:
      return 0;       /* initial nondigit */

    case 1:             /* a -- 32 bits */
      break;

    case 2:             /* a.b -- 8.24 bits */
      if (val > 0xffffffUL) {
        return 0;
      }
      if (parts[0] > 0xff) {
        return 0;
      }
      val |= parts[0] << 24;
      break;

    case 3:             /* a.b.c -- 8.8.16 bits */
      if (val > 0xffff) {
        return 0;
      }
      if ((parts[0] > 0xff) || (parts[1] > 0xff)) {
        return 0;
      }
      val |= (parts[0] << 24) | (parts[1] << 16);
      break;

    case 4:             /* a.b.c.d -- 8.8.8.8 bits */
      if (val > 0xff) {
        return 0;
      }
      if ((parts[0] > 0xff) || (parts[1] > 0xff) || (parts[2] > 0xff)) {
        return 0;
      }
      val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
      break;
    default:
      assert(0);
      break;
    }
    if (addr) {
      ip4_addr_set_u32(addr, htonl(val));
    }
    return 1;
}
