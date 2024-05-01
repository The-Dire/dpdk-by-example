#include "arp.h"

// 查表操作,获取发送arp replay的对端的mac地址
uint8_t* ht_get_dst_macaddr(uint32_t dip) {
  struct list_head *cursor;
  list_for_each(cursor, &arp_table) {
    arp_entry *tmp = list_entry(cursor, arp_entry, entry);
    if (dip == tmp->ip) { // dip在表中被查到则找到了
      return tmp->hw_addr;
    }
  }
  return NULL;
}

/* arp组包发包相关模块 */
// 构建arp response包. 自定义opcode 1为request,2为response
int ht_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  // 如果目的mac与g_default_arp_mac地址一致,还要特殊处理以太网头mac地址字段
  if (!strncmp((const char *)dst_mac, (const char *)g_default_arp_mac, RTE_ETHER_ADDR_LEN)) {
    uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
    rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
  }
  else {
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
  }
  eth->ether_type = rte_htons(RTE_ETHER_TYPE_ARP);

  // 2 arp 
  struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
  arp->arp_hardware = rte_htons(1);
  arp->arp_protocol = rte_htons(RTE_ETHER_TYPE_IPV4);
  arp->arp_hlen = RTE_ETHER_ADDR_LEN; // 硬件地址长度
  arp->arp_plen = sizeof(uint32_t); // 软件地址长度
  arp->arp_opcode = rte_htons(opcode); // 2为response,1为request
  rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

  arp->arp_data.arp_sip = sip;
  arp->arp_data.arp_tip = dip;
  
  return 0;
}

// 发送arp response
struct rte_mbuf *ht_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
  // 14 + 28, eth头14字节,arp头28字节
  const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "ht_send_arp: rte_pktmbuf_alloc\n");
  }

  mbuf->pkt_len = total_length;
  mbuf->data_len = total_length;

  uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
  ht_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

  return mbuf;
}

void ht_arp_out_callback(__attribute__((unused)) struct rte_timer *tim,
  void *arg) {
  // 发送arp request所需的mbuf
  struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
  // 不直接发送,送入待发送队列中等待其他核心进行发送处理
  // (这里为了简单还是在main中发送的,而收包则是存入recv_ring里
  // 由另外一个绑核线程进行协议解析)
  struct rte_ring *send_ring = g_ring->send_ring;
  
  // 定时发送
  int i = 0;
  for (i = 1; i <= 254; i++) { // 局域网每一台机器都发送一个arp request
    uint32_t dst_ip = (g_local_ip & 0x00FFFFFF) | (0xFF000000 & (i << 24));

    char ip_buf[16] = {0};
    printf("arp ---> src: %s ----- %d\n", inet_ntoa2(dst_ip, ip_buf), i);

    struct rte_mbuf* arp_buf = NULL;
    uint8_t *dst_mac = ht_get_dst_macaddr(dst_ip);
    // 如果arp table里面没有对应dst ip地址,那么arp hdr和ether hdr中的dmac字段自己构造发送.
    if (dst_mac == NULL) {
			// arp hdr --> mac : FF:FF:FF:FF:FF:FF
			// ether hdr --> mac : 00:00:00:00:00:00
			arp_buf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, g_default_arp_mac, g_local_ip, dst_ip); 
    }
    else { // 常规的arp request发送
      arp_buf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dst_mac, g_local_ip, dst_ip);
    }

    //rte_eth_tx_burst(g_dpdk_port_id, 0, &arp_buf, 1);
    //rte_pktmbuf_free(arp_buf);
    // 待发送的arp包存入队列中
    rte_ring_mp_enqueue_burst(send_ring, (void**)&arp_buf, 1, NULL);
  }
}

int ht_arp_in(struct rte_mbuf *arp_mbuf, struct rte_mempool *mbuf_pool) {
  // 获取arp头
  struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(arp_mbuf, 
      struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
  
  char ip_buf[16] = {0};
  printf("arp ---> src: %s ", inet_ntoa2(arp_hdr->arp_data.arp_tip, ip_buf));
  printf(" local: %s \n", inet_ntoa2(g_local_ip, ip_buf));
  // 由于arp request是广播,判断目标地址相同才返回arp response
  if (arp_hdr->arp_data.arp_tip == g_local_ip) {
    if (arp_hdr->arp_opcode == rte_htons(RTE_ARP_OP_REQUEST)) {
      printf("arp --> request\n");
      // 接收到arp request包后返回arp response。注:request里的源ip是response里的目的ip
      struct rte_mbuf *arp_buf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, arp_hdr->arp_data.arp_sha.addr_bytes, 
        arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip);
      //rte_eth_tx_burst(g_dpdk_port_id, 0, &arpbuf, 1);
      //rte_pktmbuf_free(arp_buf);
      // 带有rte_eth_tx_burst改成全改成入队即可.放入到send ring中处理
      rte_ring_mp_enqueue_burst(g_ring->send_ring, (void**)&arp_buf, 1, NULL);
      // 处理arp响应的流程(这里对端发送arp reply,这个值要记录到arp表里)
    }
    else if (arp_hdr->arp_opcode == rte_htons(RTE_ARP_OP_REPLY)) {
      printf("arp --> reply\n");
      
      uint8_t *hw_addr = ht_get_dst_macaddr(arp_hdr->arp_data.arp_sip);
      // 如果接收到了arp reply,但是查表找不到对应的mac地址则插入表中
      if (hw_addr == NULL) {
        // 结点初始化
        arp_entry *new_entry = rte_malloc("arp_entry", sizeof(arp_entry), 0);

        new_entry->ip = arp_hdr->arp_data.arp_sip;
        rte_memcpy(new_entry->hw_addr, arp_hdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
        new_entry->type = 0;
        // 线程不安全，这里应该改为cas原子操作
        list_add_tail(&new_entry->entry, &arp_table);
        arp_count++;
      }

      struct list_head *iter;
      list_for_each(iter, &arp_table) {
        arp_entry *addr = list_entry(iter, arp_entry, entry);
        char ip_buf[16] = {0};

        print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)addr->hw_addr);

        printf(" ip : %s \n", inet_ntoa2(addr->ip, ip_buf));
      }

    }
    rte_pktmbuf_free(mbufs[i]);
    return 1;
  }
  else {
    return 0;
  }
}
/* end of arp */