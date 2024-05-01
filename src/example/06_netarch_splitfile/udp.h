#ifndef __HT_UDP_H__
#define __HT_UDP_H__

#include "common.h"

void ht_udp_out(struct rte_ipv4_hdr *iphdr, struct rte_mempool *udp_pool);

#endif