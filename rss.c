#include "rss.h"

#include <rte_thash.h>

//The key mTCP uses, for some reason, this key is different than
//the key they describe in their paper
const uint32_t rss_hash_key[10] = {
    0x05050505, 0x05050505,
    0x05050505, 0x05050505,
    0x05050505, 0x05050505,
    0x05050505, 0x05050505,
    0x05050505, 0x05050505,
};

static uint32_t converted_rss_hash_key[sizeof(rss_hash_key)] = {};

void
lwip_dpdk_rss_init()
{
    //this actually should not matter as all that rte_convert_rss_key does
    //is convert to big endian but rss_hash_key should be invariant to that
    //(as it contains only identical bytes).
    //But for the sake of documentation, do it anyways, so nobody is suprised
    //when they change the rss_hash_key
    rte_convert_rss_key(rss_hash_key, converted_rss_hash_key, sizeof(rss_hash_key)*sizeof(uint32_t));
}

uint32_t
lwip_dpdk_rss_cached_value_for_rss(uint32_t sip, uint32_t dip)
{
    uint32_t tuple[4] = {sip, dip, 0};
    return rte_softrss_be(tuple, 3, (uint8_t*)converted_rss_hash_key);
}

uint32_t
lwip_dpdk_rss_for_ports(uint32_t cached_value, uint16_t sp, uint16_t dp)
{
    uint32_t i;
    uint32_t ret = cached_value;
    uint32_t input_value = ((uint32_t)sp) << 16 | dp;

    for (i = 0; i < 32; i++) {
        if (input_value & (1 << (31 - i))) {
            ret ^= ((const uint32_t *)converted_rss_hash_key)[2] << i |
                (uint32_t)((uint64_t)(((const uint32_t *)converted_rss_hash_key)[2 + 1]) >> (32 - i));
        }
    }

    return ret;
}

unsigned int
lwip_dpdk_rss_queue_for_hash(uint32_t hash, uint32_t number_of_queues)
{
    //NOTE: according to the datasheets for X540 only the lower 7 bits
    //are used to calculate the lookup position.
    //The XL710 datasheet, as far as I can decipher it can be configured
    //to use the lower 9 bits - but as 2^9 is divisible by 2^7 this should
    //not be a problem
    return (hash & 0x7f) % number_of_queues;
}
