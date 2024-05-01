#ifndef __HT_ARP_H__
#define __HT_ARP_H__
#include "common.h"

int ht_ip_in(struct rte_mbuf *ip_mbuf, struct rte_mempool *ip_pool);
int ht_ip_out();


#endif