#include "icmp.h"

/* icmp组包发包相关模块 */
uint16_t ht_checksum(void *addr, int count) {
  
  register long sum = 0;
  uint16_t *ptr = addr;

  while (count > 1) {
    sum += *ptr++; // uint16_t 2字节
    count -= 2;
  }

  /*  Add left-over byte, if any */
  if (count > 0) {
    sum += *(uint8_t*)addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return ~sum;
}

int ht_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
  uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

  // 1 ether
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
  eth->ether_type = rte_htons(RTE_ETHER_TYPE_IPV4);

  // 2 ip
  struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
  ip->version_ihl = 0x45;
  ip->type_of_service = 0;
  ip->total_length = rte_htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64; // ttl = 64
  ip->next_proto_id = IPPROTO_ICMP;
  ip->src_addr = sip;
  ip->dst_addr = dip;

  ip->hdr_checksum = 0;
  ip->hdr_checksum = rte_ipv4_cksum(ip);

  // 3 icmp 
  struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
  icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY; // 返回icmp reply包
  icmp->icmp_code = 0;
  icmp->icmp_ident = id;		// icmp的identifier字段
  icmp->icmp_seq_nb = seqnb;	// icmp的sequence number字段

  icmp->icmp_cksum = 0;
  icmp->icmp_cksum = ht_checksum((void*)icmp, sizeof(struct rte_icmp_hdr));

  return 0;
}

struct rte_mbuf *ht_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
  uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb) {

  const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
  }


  mbuf->pkt_len = total_length;
  mbuf->data_len = total_length;

  uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
  ht_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);

  return mbuf;
}

void ht_icmp_out(struct rte_ipv4_hdr *iphdr, struct rte_mempool *icmp_pool)
{
  struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
  char ip_buf[16] = {0};
  printf("icmp ---> src: %s ", inet_ntoa2(iphdr->src_addr, ip_buf));
  // 接收到的是icmp request,回一个icmp reply
  if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

    printf(" local: %s , type : %d\n", inet_ntoa2(iphdr->dst_addr, ip_buf), icmphdr->icmp_type);
    
    struct rte_mbuf *txbuf = ht_send_icmp(icmp_pool, ehdr->s_addr.addr_bytes,
      iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

    rte_ring_mp_enqueue_burst(g_ring->send_ring, (void**)&txbuf, 1, NULL);

    rte_pktmbuf_free(mbufs[i]);
  }
}
/* end of icmp */