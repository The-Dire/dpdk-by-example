#include "ip.h"
#include "icmp.h"

int ht_ip_in(struct rte_mbuf* ip_mbuf, struct rte_mempool *ip_pool)
{
  // 解析ip协议头部
  struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(ip_mbuf, struct rte_ipv4_hdr *, 
  sizeof(struct rte_ether_hdr));
  // 对是udp的包做处理
  if (iphdr->next_proto_id == IPPROTO_UDP) {
  // udp的头
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

    // 发送包所需要的六元组dmac,sip,dip,sport,dport获取并填充
    // 由于是发echo reply所以需要交换。比如dmac是取获取到的包的smac
    rte_memcpy(g_dst_mac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

    rte_memcpy(&g_src_ip, &iphdr->dst_addr, sizeof(uint32_t));
    rte_memcpy(&g_dst_ip, &iphdr->src_addr, sizeof(uint32_t));

    rte_memcpy(&g_src_port, &udphdr->dst_port, sizeof(uint16_t));
    rte_memcpy(&g_dst_port, &udphdr->src_port, sizeof(uint16_t));

    uint16_t length = rte_ntohs(udphdr->dgram_len); // 两个字节以上都要转换ntohs
    *((char*)udphdr + length) = '\0';	// 最后一段置为0
    // 打印接收到的udp数据
    char ip_buf[16] = {0};
    printf("src: %s:%d, ", inet_ntoa2(iphdr->src_addr, ip_buf), udphdr->src_port);

    printf("dst: %s:%d, %s\n", inet_ntoa2(iphdr->src_addr, ip_buf), udphdr->src_port, (char *)(udphdr+1));

    // 发送udp echo
    struct rte_mbuf *txbuf = ht_send_udp(ip_mbuf, (uint8_t *)(udphdr+1), length);
    // rte_eth_tx_burst(g_dpdk_port_id, 0, &txbuf, 1);// rte_eth_rx_burst发送数据
    // rte_pktmbuf_free(txbuf); // 发送用的mbuf同样放回到内存池中
    // 发送udp echo通过送入队列中，在main中从队列取出再发送
    rte_ring_mp_enqueue_burst(send_ring, (void**)&txbuf, 1, NULL);

    rte_pktmbuf_free(ip_mbuf); // 放回内存池
  }

  // icmp包的处理
  if (iphdr->next_proto_id == IPPROTO_ICMP) {
    ht_icmp_out(iphdr, ip_pool);
  }
}