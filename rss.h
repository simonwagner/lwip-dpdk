#ifndef RSS_H
#define RSS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const uint32_t rss_hash_key[10];

void lwip_dpdk_rss_init();
uint32_t lwip_dpdk_rss_cached_value_for_rss(uint32_t sip, uint32_t dip);
uint32_t lwip_dpdk_rss_for_ports(uint32_t cached_value, uint16_t sp, uint16_t dp);
unsigned int lwip_dpdk_rss_queue_for_hash(uint32_t hash, uint32_t number_of_queues);

#ifdef __cplusplus
}
#endif

#endif // RSS_H
