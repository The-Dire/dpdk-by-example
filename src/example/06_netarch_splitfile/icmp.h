#ifndef __HT_ICMP_H__
#define __HT_ICMP_H__

#include "common.h"

uint16_t ht_checksum(void *addr, int count);

void ht_icmp_out(struct rte_ipv4_hdr *iphdr, struct rte_mempool *icmp_pool);

#endif