#ifndef __HT_ICMP_H__
#define __HT_ICMP_H__

#include "common.h"

uint16_t ht_checksum(void *addr, int count);

int ht_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
  uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb);

struct rte_mbuf *ht_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
  uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb);

#endif