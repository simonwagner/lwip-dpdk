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
    //From mTCP:
    /*-------------------------------------------------------------------*/
    /* RSS redirection table is in the little endian byte order (intel)  */
    /*                                                                   */
    /* idx: 0 1 2 3 | 4 5 6 7 | 8 9 10 11 | 12 13 14 15 | 16 17 18 19 ...*/
    /* val: 3 2 1 0 | 7 6 5 4 | 11 10 9 8 | 15 14 13 12 | 19 18 17 16 ...*/
    /* qid = val % num_queues */
    /*-------------------------------------------------------------------*/

    uint32_t idx = hash;
    //I could make this totally unreadable with bit fiddeling,
    //but I believe in optimizing compilers
    uint32_t val = (idx / 4) * 4 + (4 - idx % 4);

    return hash % number_of_queues;
}
