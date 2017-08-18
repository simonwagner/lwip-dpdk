#include "etharp_private.h"

#include <time.h>
#include <limits.h>

#include <rte_malloc.h>

#include <lwip/opt.h>
#include <lwip/stats.h>
#include <lwip/snmp.h>
#include <lwip/dhcp.h>
#include <lwip/autoip.h>
#include <lwip/pbuf.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/ip4.h>
#include <netif/ethernet.h>
#include <lwip/prot/etharp.h>

#include "ethif_private.h"
#include "context_private.h"
#include "etharp_master.h"

#define LWIP_DPDK_ARP_QUEUE_TIMEOUT 30
#define LWIP_DPDK_ARP_REQUEST_TIMEOUT 10

#define ETHARP_FLAG_TRY_HARD     1 << 1
#define ETHARP_FLAG_FIND_ONLY    1 << 2

const struct eth_addr ethbroadcast = {{0xff,0xff,0xff,0xff,0xff,0xff}},
                      ethzero = {{0,0,0,0,0,0}};

static time_t start_time;

err_t
lwip_dpdk_etharp_init(struct lwip_dpdk_global_context* global_context)
{
  struct timespec clock_time;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &clock_time);

  start_time = clock_time.tv_sec;

  return ERR_OK;
}

void
lwip_dpdk_etharp_table_init(struct lwip_dpdk_arp_table* table, int seq, int socket)
{
  table->table = rte_zmalloc_socket("lwip_dpdk_arp_table_table",
                                    sizeof(struct lwip_dpdk_arp_entry)*LWIP_DPDK_ARP_TABLE_SIZE,
                                    RTE_CACHE_LINE_SIZE,
                                    socket);
  table->seq = seq;
}

err_t
lwip_dpdk_etharp_context_init(struct lwip_dpdk_context* context)
{
  int socket = rte_lcore_to_socket_id(context->lcore);

  context->arp_table = rte_zmalloc_socket("lwip_dpdk_arp_table",
                                          sizeof(struct lwip_dpdk_arp_table),
                                          RTE_CACHE_LINE_SIZE,
                                          socket);

  lwip_dpdk_etharp_table_init(context->arp_table, 0, socket);

  context->arp_queue = rte_zmalloc_socket("lwip_dpdk_arp_queue",
                                          sizeof(struct lwip_dpdk_arp_queue),
                                          RTE_CACHE_LINE_SIZE,
                                          socket);

  return ERR_OK;
}

void
lwip_dpdk_etharp_context_release(struct lwip_dpdk_context* context)
{
  if(context == NULL) {
    return;
  }

  if(context->arp_table) {
    rte_free(context->arp_table->table);
  }
  rte_free(context->arp_table);
  rte_free(context->arp_queue);
}

struct lwip_dpdk_arp_entry*
lwip_dpdk_etharp_lookup_table_entry(struct lwip_dpdk_arp_table* table, ip4_addr_t ipaddr)
{
  int i;
  for(i = 0; i < LWIP_DPDK_ARP_TABLE_SIZE; ++i) {
    struct lwip_dpdk_arp_entry* entry = &table->table[i];

    if(ipaddr.addr == entry->ipaddr.addr &&
       entry->state != ETHARP_STATE_EMPTY) {
      return entry;
    }
  }

  return NULL;
}

struct eth_addr*
lwip_dpdk_etharp_lookup_ethaddr(struct lwip_dpdk_arp_table* table, ip4_addr_t ipaddr)
{
  struct lwip_dpdk_arp_entry* entry = lwip_dpdk_etharp_lookup_table_entry(table, ipaddr);
  if(entry == NULL) {
    return NULL;
  }
  if(entry->state == ETHARP_STATE_EMPTY || entry->state == ETHARP_STATE_PENDING) {
    return NULL;
  }

  return &entry->ethaddr;
}

static u8_t
lwip_dpdk_etharp_entry_has_address(struct lwip_dpdk_arp_entry* entry)
{
  return entry->state != ETHARP_STATE_EMPTY && entry->state != ETHARP_STATE_PENDING;
}

static u8_t
lwip_dpdk_etharp_update_arp_entry(struct lwip_dpdk_arp_table* table, ip4_addr_t ipaddr, const struct eth_addr* ethaddr, enum etharp_state state, int ctime, int flags)
{
  //TODO: horrible, replace with hash table
  if(ctime < 0) {
    struct timespec clock_time;
    clock_gettime(CLOCK_MONOTONIC_COARSE, &clock_time);

    ctime = clock_time.tv_sec - start_time;
  }

  int i;
  int oldest_entry_i = 0;
  int oldest_ctime = INT_MAX;
  int first_empty_i = -1;
  for(i = 0; i < LWIP_DPDK_ARP_TABLE_SIZE; ++i) {
    struct lwip_dpdk_arp_entry* entry = &table->table[i];

    if(entry->state == ETHARP_STATE_STATIC) {
      continue; //ignore static entries, we will never update them
    }

    if(entry->state == ETHARP_STATE_EMPTY && first_empty_i < 0) {
      first_empty_i = i;
    }
    else if(ipaddr.addr == entry->ipaddr.addr) {
      memcpy(&entry->ethaddr, ethaddr, sizeof(struct eth_addr));
      entry->ctime = ctime;
      entry->state = state;
      return 1;
    }

    if(entry->ctime < oldest_ctime) {
      oldest_ctime = entry->ctime;
      oldest_entry_i = i;
    }
  }

  if(flags & ETHARP_FLAG_FIND_ONLY) {
    //abort if ETHARP_FLAG_FIND_ONLY was given
    //we did not find the entry corresponding to the
    //given address
    return 0;
  }

  //We did not find an entry for the ip address, so add a new entry
  if(first_empty_i > 0) {
    struct lwip_dpdk_arp_entry* entry = &table->table[first_empty_i];

    memcpy(&entry->ethaddr, ethaddr, sizeof(struct eth_addr));
    entry->ctime = ctime;
    entry->state = state;
    entry->ipaddr.addr = ipaddr.addr;

    return 1;
  }
  else {
    //If the user requested it with the ETHARP_FLAG_TRY_HARD, overwrite
    //the oldest entry if there is no free space
    if(flags & ETHARP_FLAG_TRY_HARD) {
      struct lwip_dpdk_arp_entry* entry = &table->table[oldest_entry_i];

      memcpy(&entry->ethaddr, ethaddr, sizeof(struct eth_addr));
      entry->ctime = ctime;
      entry->state = state;
      entry->ipaddr.addr = ipaddr.addr;

      return 1;
    }
    else {
      return 0;
    }
  }
}

void
lwip_dpdk_arp_table_copy(struct lwip_dpdk_arp_table* src, struct lwip_dpdk_arp_table* dst)
{
  memcpy(dst->table, src->table, sizeof(struct lwip_dpdk_arp_entry) * LWIP_DPDK_ARP_TABLE_SIZE);
}

static int
lwip_dpdk_etharp_enqueue(struct lwip_dpdk_context* context, struct netif* netif, struct lwip_dpdk_arp_queue* queue, ip4_addr_t ipaddr, struct pbuf* p)
{
  struct timespec clock_time;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &clock_time);

  int now = clock_time.tv_sec - start_time;

  int i;

  struct lwip_dpdk_arp_queue_entry* entry;
  for(i = 0; i < queue->queue_length; ++i) {
    entry = &queue->queue[i];

    if(entry->ipaddr.addr == IPADDR_ANY) {
      entry->ipaddr.addr = ipaddr.addr;
      entry->q = p;
      entry->ctime = now;
      entry->netif_index = netif->num;

      return 1;
    }
    else if(now - entry->ctime > LWIP_DPDK_ARP_QUEUE_TIMEOUT) {
      //overwrite old entry that has already timed out
      struct pbuf* old_q = entry->q;

      entry->ipaddr.addr = ipaddr.addr;
      entry->q = p;
      entry->ctime = now;
      entry->netif_index = netif->num;

      context->api->_pbuf_free(old_q);
      return 1;
    }
  }

  if(queue->queue_length < LWIP_DPDK_ARP_QUEUE_SIZE) {
    entry = &queue->queue[i];
    entry->ctime = now;
    entry->ipaddr.addr = ipaddr.addr;
    entry->q = p;
    entry->netif_index = netif->num;

    return 1;
  }
  else {
    return 0; //drop packet, queue is full
  }
}

struct pbuf* lwip_dpdk_etharp_dequeue(struct lwip_dpdk_arp_queue* queue, ip4_addr_t ipaddr) //TODO: remove this
{
  int i;
  for(i = 0; i < queue->queue_length; ++i) {
    struct lwip_dpdk_arp_queue_entry* entry = &queue->queue[i];

    if(ipaddr.addr == entry->ipaddr.addr) {
      struct pbuf* q = entry->q;

      entry->ipaddr.addr = IPADDR_ANY;
      entry->q = NULL;

      if(i == queue->queue_length - 1) {
        //we removed the tail, so decrease length
        queue->queue_length--;
      }

      return q;
    }
  }

  return NULL;
}

/**
 * Send a raw ARP packet (opcode and all addresses can be modified)
 *
 * @param netif the lwip network interface on which to send the ARP packet
 * @param ethsrc_addr the source MAC address for the ethernet header
 * @param ethdst_addr the destination MAC address for the ethernet header
 * @param hwsrc_addr the source MAC address for the ARP protocol header
 * @param ipsrc_addr the source IP address for the ARP protocol header
 * @param hwdst_addr the destination MAC address for the ARP protocol header
 * @param ipdst_addr the destination IP address for the ARP protocol header
 * @param opcode the type of the ARP packet
 * @return ERR_OK if the ARP packet has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
static err_t
etharp_raw(struct netif *netif, const struct eth_addr *ethsrc_addr,
           const struct eth_addr *ethdst_addr,
           const struct eth_addr *hwsrc_addr, const ip4_addr_t *ipsrc_addr,
           const struct eth_addr *hwdst_addr, const ip4_addr_t *ipdst_addr,
           const u16_t opcode)
{
  struct pbuf *p;
  err_t result = ERR_OK;
  struct etharp_hdr *hdr;
  struct lwip_dpdk_queue_eth* lwip_dpdk_queue;
  struct lwip_dpdk_context* context;

  LWIP_ASSERT("netif != NULL", netif != NULL);

  lwip_dpdk_queue = netif_dpdk_ethif(netif);
  context = lwip_dpdk_queue->context;

  /* allocate a pbuf for the outgoing ARP request packet */
  p = context->api->_pbuf_alloc(PBUF_LINK, SIZEOF_ETHARP_HDR, PBUF_RAM);
  /* could allocate a pbuf for an ARP request? */
  if (p == NULL) {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_SERIOUS,
      ("etharp_raw: could not allocate pbuf for ARP request.\n"));
    ETHARP_STATS_INC(etharp.memerr);
    return ERR_MEM;
  }
  LWIP_ASSERT("check that first pbuf can hold struct etharp_hdr",
              (p->len >= SIZEOF_ETHARP_HDR));

  hdr = (struct etharp_hdr *)p->payload;
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_raw: sending raw ARP packet.\n"));
  hdr->opcode = PP_HTONS(opcode);

  LWIP_ASSERT("netif->hwaddr_len must be the same as ETH_HWADDR_LEN for etharp!",
              (netif->hwaddr_len == ETH_HWADDR_LEN));

  /* Write the ARP MAC-Addresses */
  ETHADDR16_COPY(&hdr->shwaddr, hwsrc_addr);
  ETHADDR16_COPY(&hdr->dhwaddr, hwdst_addr);
  /* Copy struct ip4_addr2 to aligned ip4_addr, to support compilers without
   * structure packing. */
  IPADDR2_COPY(&hdr->sipaddr, ipsrc_addr);
  IPADDR2_COPY(&hdr->dipaddr, ipdst_addr);

  hdr->hwtype = PP_HTONS(HWTYPE_ETHERNET);
  hdr->proto = PP_HTONS(ETHTYPE_IP);
  /* set hwlen and protolen */
  hdr->hwlen = ETH_HWADDR_LEN;
  hdr->protolen = sizeof(ip4_addr_t);

  context->api->_ethernet_output(netif, p, ethsrc_addr, ethdst_addr, ETHTYPE_ARP);

  ETHARP_STATS_INC(etharp.xmit);
  /* free ARP query packet */
  context->api->_pbuf_free(p);
  p = NULL;

  return result;
}

/**
 * Send an ARP request packet asking for ipaddr to a specific eth address.
 * Used to send unicast request to refresh the ARP table just before an entry
 * times out
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @param hw_dst_addr the ethernet address to send this packet to
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
static err_t
etharp_request_dst(struct netif *netif, const ip4_addr_t *ipaddr, const struct eth_addr* hw_dst_addr)
{
  return etharp_raw(netif, (struct eth_addr *)netif->hwaddr, hw_dst_addr,
                    (struct eth_addr *)netif->hwaddr, netif_ip4_addr(netif), &ethzero,
                    ipaddr, ARP_REQUEST);
}

/**
 * Send an ARP request packet asking for ipaddr.
 *
 * @param netif the lwip network interface on which to send the request
 * @param ipaddr the IP address for which to ask
 * @return ERR_OK if the request has been sent
 *         ERR_MEM if the ARP packet couldn't be allocated
 *         any other err_t on failure
 */
static err_t
etharp_request(struct netif *netif, const ip4_addr_t *ipaddr)
{
  LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_request: sending ARP request.\n"));
  return etharp_request_dst(netif, ipaddr, &ethbroadcast);
}

/**
 * Determine if an address is a broadcast address on a network interface
 *
 * @param addr address to be checked
 * @param netif the network interface against which the address is checked
 * @return returns non-zero if the address is a broadcast address
 */
static u8_t
_ip4_addr_isbroadcast(ip4_addr_t ipaddr, const struct netif *netif)
{
  u32_t addr = ipaddr.addr;

  /* all ones (broadcast) or all zeroes (old skool broadcast) */
  if ((~addr == IPADDR_ANY) ||
      (addr == IPADDR_ANY)) {
    return 1;
  /* no broadcast support on this network interface? */
  } else if ((netif->flags & NETIF_FLAG_BROADCAST) == 0) {
    /* the given address cannot be a broadcast address
     * nor can we check against any broadcast addresses */
    return 0;
  /* address matches network interface address exactly? => no broadcast */
  } else if (addr == ip4_addr_get_u32(netif_ip4_addr(netif))) {
    return 0;
  /*  on the same (sub) network... */
  } else if (ip4_addr_netcmp(&ipaddr, netif_ip4_addr(netif), netif_ip4_netmask(netif))
         /* ...and host identifier bits are all ones? =>... */
          && ((addr & ~ip4_addr_get_u32(netif_ip4_netmask(netif))) ==
           (IPADDR_BROADCAST & ~ip4_addr_get_u32(netif_ip4_netmask(netif))))) {
    /* => network broadcast address */
    return 1;
  } else {
    return 0;
  }
}

/**
 * Resolve and fill-in Ethernet address header for outgoing IP packet.
 *
 * For IP multicast and broadcast, corresponding Ethernet addresses
 * are selected and the packet is transmitted on the link.
 *
 * For unicast addresses, the packet is submitted to etharp_query(). In
 * case the IP address is outside the local network, the IP address of
 * the gateway is used.
 *
 * @param netif The lwIP network interface which the IP packet will be sent on.
 * @param q The pbuf(s) containing the IP packet to be sent.
 * @param ipaddr The IP address of the packet destination.
 *
 * @return
 * - ERR_RTE No route to destination (no gateway to external networks),
 * or the return type of either etharp_query() or ethernet_output().
 */
err_t
lwip_dpdk_etharp_output(struct netif *netif, struct pbuf *q, const ip4_addr_t *ipaddr)
{
  const struct eth_addr *dest;
  struct eth_addr mcastaddr;
  const ip4_addr_t *dst_addr = ipaddr;
  struct lwip_dpdk_context* context;
  struct lwip_dpdk_queue_eth* lwip_dpdk_queue;

  LWIP_ASSERT("netif != NULL", netif != NULL);
  LWIP_ASSERT("q != NULL", q != NULL);
  LWIP_ASSERT("ipaddr != NULL", ipaddr != NULL);

  lwip_dpdk_queue = netif_dpdk_ethif(netif);
  context = lwip_dpdk_queue->context;

  /* Determine on destination hardware address. Broadcasts and multicasts
   * are special, other IP addresses are looked up in the ARP table. */

  /* broadcast destination IP address? */
  if (_ip4_addr_isbroadcast(*ipaddr, netif)) {
    /* broadcast on Ethernet also */
    dest = (const struct eth_addr *)&ethbroadcast;
  /* multicast destination IP address? */
  } else if (ip4_addr_ismulticast(ipaddr)) {
    /* Hash IP multicast address to MAC address.*/
    mcastaddr.addr[0] = LL_IP4_MULTICAST_ADDR_0;
    mcastaddr.addr[1] = LL_IP4_MULTICAST_ADDR_1;
    mcastaddr.addr[2] = LL_IP4_MULTICAST_ADDR_2;
    mcastaddr.addr[3] = ip4_addr2(ipaddr) & 0x7f;
    mcastaddr.addr[4] = ip4_addr3(ipaddr);
    mcastaddr.addr[5] = ip4_addr4(ipaddr);
    /* destination Ethernet address is multicast */
    dest = &mcastaddr;
  /* unicast destination IP address? */
  } else {
    /* outside local network? if so, this can neither be a global broadcast nor
       a subnet broadcast. */
    if (!ip4_addr_netcmp(ipaddr, netif_ip4_addr(netif), netif_ip4_netmask(netif)) &&
        !ip4_addr_islinklocal(ipaddr)) {
      /* interface has default gateway? */
      if (!ip4_addr_isany_val(*netif_ip4_gw(netif))) {
        /* send to hardware address of default gateway IP address */
        dst_addr = netif_ip4_gw(netif);
        /* no default gateway available */
      } else {
        /* no route to destination error (default gateway missing) */
        return ERR_RTE;
      }
    }

    struct lwip_dpdk_arp_entry* arp_entry = lwip_dpdk_etharp_lookup_table_entry(context->arp_table, *dst_addr);
    if(arp_entry != NULL && lwip_dpdk_etharp_entry_has_address(arp_entry)) {
      return context->api->_ethernet_output(netif, q, (struct eth_addr*)(netif->hwaddr), &arp_entry->ethaddr, ETHTYPE_IP);
    }
    else {
      int ret = ERR_OK;
      if(arp_entry == NULL) {
        //send request if no arp entry has been found
        //do not send request if it is pending
        ret = etharp_request(netif, dst_addr);
        //mark entry as pending in the ARP table
        lwip_dpdk_etharp_update_arp_entry(context->arp_table, *dst_addr, &ethzero, ETHARP_STATE_PENDING, -1, ETHARP_FLAG_TRY_HARD);
      }
      if(ret == ERR_OK) {
        //enqueue packet to send it later when reply arrives
        lwip_dpdk_etharp_enqueue(context, netif, context->arp_queue, *dst_addr, q);
      }

      return ret;
    }
  }

  /* continuation for multicast/broadcast destinations */
  /* obtain source Ethernet address of the given interface */
  /* send packet directly on the link */
  return context->api->_ethernet_output(netif, q, (struct eth_addr*)(netif->hwaddr), dest, ETHTYPE_IP);
}

err_t
lwip_dpdk_etharp_queue_drain(struct lwip_dpdk_context* context, int now)
{
  /* drain the queue, send packets from the queue that we can resolve now */
  LWIP_ASSERT("context != NULL", context != NULL);

  struct lwip_dpdk_arp_queue* queue = context->arp_queue;

  int i;
  err_t err;
  int last_non_null_entry = -1;

  for(i = 0; i < queue->queue_length; ++i) {
    struct lwip_dpdk_arp_queue_entry* entry = &queue->queue[i];
    if(entry->ipaddr.addr == IPADDR_ANY) {
      continue; //ignore empty entry
    }
    if(entry->ctime - now > LWIP_DPDK_ARP_QUEUE_TIMEOUT) {
      //expired entry, remove it from the queue and ignore it
      entry->ipaddr.addr = IPADDR_ANY;
      context->api->_pbuf_free(entry->q);
      entry->q = NULL;
      continue;
    }

    struct netif* netif = &context->netifs[entry->netif_index];

    struct eth_addr* dest = lwip_dpdk_etharp_lookup_ethaddr(context->arp_table, entry->ipaddr); /*this is horrible - TODO: use a hash table or something else sensible with O(1) for lookup */

    if(dest != NULL) {
      err = context->api->_ethernet_output(netif, entry->q, (struct eth_addr*)(netif->hwaddr), dest, ETHTYPE_IP);
      if(err != ERR_OK) {
        return err;
      }

      entry->ipaddr.addr = IPADDR_ANY;
      entry->q = NULL;
    }
    else {
      last_non_null_entry = i;
    }
  }

  //update queue length - we keep track of the length
  //so we do not have to check each time for entries in
  //the whole queue (even if it is empty)
  queue->queue_length = last_non_null_entry + 1;

  return ERR_OK;
}

void
lwip_dpdk_etharp_table_expire(struct lwip_dpdk_context *context, int now)
{
  struct lwip_dpdk_arp_table* table = context->arp_table;
  int i;

  for(i = 0; i < LWIP_DPDK_ARP_TABLE_SIZE; ++i) {
    struct lwip_dpdk_arp_entry* entry = &table->table[i];

    //remove old entries that are expired
    if(entry->state == ETHARP_STATE_PENDING &&
       now - entry->ctime > LWIP_DPDK_ARP_REQUEST_TIMEOUT) {
      entry->state = ETHARP_STATE_EMPTY;
      entry->ctime = 0;
      entry->ipaddr.addr = IPADDR_ANY;
      memset(&entry->ethaddr, 0, sizeof(struct ether_addr));
    }
  }
}

void
lwip_dpdk_etharp_sync_with_master(struct lwip_dpdk_context *context)
{
  struct lwip_dpdk_arp_table* table = context->arp_table;
  struct lwip_dpdk_master_arp_table* global_table = context->global_arp_table;
  int master_seq = global_table->seq;
  if(master_seq > table->seq) {
    pthread_rwlock_rdlock(&global_table->lock);

    //copy the entries from the global table to the local table
    //that should resolve all pending entries
    struct lwip_dpdk_arp_table* ro_table = global_table->ro_table;
    int i;
    for(i = 0; i < LWIP_DPDK_ARP_TABLE_SIZE; ++i) {
      struct lwip_dpdk_arp_entry* entry = &ro_table->table[i];
      if(ro_table->table[i].state == ETHARP_STATE_STABLE ||
         ro_table->table[i].state == ETHARP_STATE_STATIC) {
        //this will either update an existing entry or insert it
        //into the table, but it will not overwrite any existing
        //entries
        lwip_dpdk_etharp_update_arp_entry(table,
                                          entry->ipaddr,
                                          &entry->ethaddr,
                                          entry->state,
                                          entry->ctime,
                                          0);
      }
    }

    table->seq = master_seq;

    pthread_rwlock_unlock(&global_table->lock);
  }
}

void
lwip_dpdk_etharp_tmr(struct lwip_dpdk_context *context)
{
  LWIP_ASSERT("context != NULL", context != NULL);

  struct lwip_dpdk_arp_queue* queue = context->arp_queue;

  struct timespec clock_time;

  clock_gettime(CLOCK_MONOTONIC_COARSE, &clock_time);
  int now = clock_time.tv_sec - start_time;

  lwip_dpdk_etharp_sync_with_master(context);

  if(queue->queue_length > 0) {
    lwip_dpdk_etharp_queue_drain(context, now);
  }

  if(now % 10) { //trigger expiration check every 10sec
    lwip_dpdk_etharp_table_expire(context, now);
  }
}

void
lwip_dpdk_etharp_input(struct pbuf *p, struct netif *netif)
{
  LWIP_ERROR("netif != NULL", (netif != NULL), return;);

  struct lwip_dpdk_queue_eth* lwip_dpdk_queue;
  struct lwip_dpdk_context* context;

  lwip_dpdk_queue = netif_dpdk_ethif(netif);
  context = lwip_dpdk_queue->context;

  lwip_dpdk_etharp_handle_input_for_table(context, p, netif, context->arp_table);
}

void
lwip_dpdk_etharp_handle_input_for_table(struct lwip_dpdk_context* context, struct pbuf *p, struct netif *netif, struct lwip_dpdk_arp_table* table)
{
  struct etharp_hdr *hdr;
  /* these are aligned properly, whereas the ARP header fields might not be */
  ip4_addr_t sipaddr, dipaddr;
  u8_t for_us;

  hdr = (struct etharp_hdr *)p->payload;

  /* RFC 826 "Packet Reception": */
  if ((hdr->hwtype != PP_HTONS(HWTYPE_ETHERNET)) ||
      (hdr->hwlen != ETH_HWADDR_LEN) ||
      (hdr->protolen != sizeof(ip4_addr_t)) ||
      (hdr->proto != PP_HTONS(ETHTYPE_IP)))  {
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE | LWIP_DBG_LEVEL_WARNING,
      ("etharp_input: packet dropped, wrong hw type, hwlen, proto, protolen or ethernet type (%"U16_F"/%"U16_F"/%"U16_F"/%"U16_F")\n",
      hdr->hwtype, (u16_t)hdr->hwlen, hdr->proto, (u16_t)hdr->protolen));
    ETHARP_STATS_INC(etharp.proterr);
    ETHARP_STATS_INC(etharp.drop);
    context->api->_pbuf_free(p);
    return;
  }
  ETHARP_STATS_INC(etharp.recv);

  /* Copy struct ip4_addr2 to aligned ip4_addr, to support compilers without
   * structure packing (not using structure copy which breaks strict-aliasing rules). */
  IPADDR2_COPY(&sipaddr, &hdr->sipaddr);
  IPADDR2_COPY(&dipaddr, &hdr->dipaddr);

  /* this interface is not configured? */
  if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
    for_us = 0;
  } else {
    /* ARP packet directed to us? */
    for_us = (u8_t)ip4_addr_cmp(&dipaddr, netif_ip4_addr(netif));
  }

  /* ARP message directed to us?
      -> add IP address in ARP cache; assume requester wants to talk to us,
         can result in directly sending the queued packets for this host.
     ARP message not directed to us?
      ->  update the source IP address in the cache, if present */
  u8_t did_change = lwip_dpdk_etharp_update_arp_entry(table, sipaddr, &(hdr->shwaddr),
                                                     ETHARP_STATE_STABLE, -1,
                                                     for_us ? ETHARP_FLAG_TRY_HARD : ETHARP_FLAG_FIND_ONLY);
  if(did_change) {
    table->seq += 1;
  }

  /* now act on the message itself */
  switch (hdr->opcode) {
  /* ARP request? */
  case PP_HTONS(ARP_REQUEST):
    /* ARP request. If it asked for our address, we send out a
     * reply. In any case, we time-stamp any existing ARP entry,
     * and possibly send out an IP packet that was queued on it. */

    LWIP_DEBUGF (ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP request\n"));
    /* ARP request for our address? */
    if (for_us) {

      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: replying to ARP request for our IP address\n"));
      /* Re-use pbuf to send ARP reply.
         Since we are re-using an existing pbuf, we can't call etharp_raw since
         that would allocate a new pbuf. */
      hdr->opcode = PP_HTONS(ARP_REPLY);

      IPADDR2_COPY(&hdr->dipaddr, &hdr->sipaddr);
      IPADDR2_COPY(&hdr->sipaddr, netif_ip4_addr(netif));

      LWIP_ASSERT("netif->hwaddr_len must be the same as ETH_HWADDR_LEN for etharp!",
                  (netif->hwaddr_len == ETH_HWADDR_LEN));

      /* hwtype, hwaddr_len, proto, protolen and the type in the ethernet header
         are already correct, we tested that before */

      ETHADDR16_COPY(&hdr->dhwaddr, &hdr->shwaddr);
      ETHADDR16_COPY(&hdr->shwaddr, netif->hwaddr);

      /* return ARP reply */
      context->api->_ethernet_output(netif, p, &hdr->shwaddr, &hdr->dhwaddr, ETHTYPE_ARP);

    /* we are not configured? */
    } else if (ip4_addr_isany_val(*netif_ip4_addr(netif))) {
      /* { for_us == 0 and netif->ip_addr.addr == 0 } */
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: we are unconfigured, ARP request ignored.\n"));
    /* request was not directed to us */
    } else {
      /* { for_us == 0 and netif->ip_addr.addr != 0 } */
      LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP request was not for us.\n"));
    }
    break;
  case PP_HTONS(ARP_REPLY):
    /* ARP reply. We already updated the ARP cache earlier. */
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: incoming ARP reply\n"));
    break;
  default:
    LWIP_DEBUGF(ETHARP_DEBUG | LWIP_DBG_TRACE, ("etharp_input: ARP unknown opcode type %"S16_F"\n", htons(hdr->opcode)));
    ETHARP_STATS_INC(etharp.err);
    break;
  }
  /* free ARP packet */
  context->api->_pbuf_free(p);
}

void
lwip_dpdk_etharp_cleanup(struct lwip_dpdk_context* context)
{

}
