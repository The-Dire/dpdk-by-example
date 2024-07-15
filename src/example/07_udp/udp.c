#include "udp.h"
#include "ht_utils.h"
#include "arp.h"

struct udp_sock_fd *g_lhost = NULL;

/* udp sock fd */
int get_fd_frombitmap(void) {
  int fd = DEFAULT_FD_NUM;
  return fd;
}

struct udp_sock_fd * get_hostinfo_fromfd(int sockfd) {
  struct udp_sock_fd *host;

  for (host = g_lhost; host != NULL;host = host->next) {
    if (sockfd == host->fd) {
      return host;
    }
  }
  return NULL;
}

struct udp_sock_fd * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {
  struct udp_sock_fd *host;

  for (host = g_lhost; host != NULL;host = host->next) {
    if (dip == host->localip && port == host->localport && proto == host->protocol) {
      return host;
    }
  }

  return NULL;
}

// udp包的处理(从旧的pkt_process中剥离出来).只做数据包的解析.
// 1.解析数据,填充offload 2.放入到recv buffer里面
int ht_udp_process(struct rte_mbuf *udp_mbuf) {
  // ipv4头和udp头获取
  struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udp_mbuf, struct rte_ipv4_hdr *, 
        sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

  // 调试用
  char ip_buf[16] = {0};
  printf("udp_process ---> src: %s:%d \n", inet_ntoa2(iphdr->src_addr, ip_buf), rte_ntohs(udphdr->src_port));
  // 通过ip和port获取udp sock结构
  struct udp_sock_fd *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
  if (host == NULL) {
    rte_pktmbuf_free(udp_mbuf);
    return -3;
  }

  struct udp_payload *payload = rte_malloc("payload", sizeof(struct udp_payload), 0);
  if (payload == NULL) {
    rte_pktmbuf_free(udp_mbuf);
    return -1;
  }

  payload->sip = iphdr->src_addr;
  payload->sport = udphdr->src_port;
  payload->dip = iphdr->dst_addr;
  payload->dport = udphdr->dst_port;
  
  payload->protocol = IPPROTO_UDP;
  payload->length = rte_ntohs(udphdr->dgram_len);
  // payloadlen = total len - udp header len
  payload->data = rte_malloc("unsigned char *", payload->length - sizeof(struct rte_udp_hdr), 0);
  if (payload->data == NULL) {
    rte_pktmbuf_free(udp_mbuf);
    rte_free(payload);
    return -2;
  }
  // 接收到的udp payload赋值
  rte_memcpy(payload->data, (uint8_t *)(udphdr + 1), payload->length - sizeof(struct rte_udp_hdr));

  rte_ring_mp_enqueue(host->rcvbuf, payload);

	pthread_mutex_lock(&host->mutex);
	pthread_cond_signal(&host->cond);
	pthread_mutex_unlock(&host->mutex);

	rte_pktmbuf_free(udp_mbuf);

	return 0;
}

/* udp组包发包相关模块 */
// 构建一个最简单的udp包,data参数是要发送的udp的payload
static int ht_encode_udp_packet(uint8_t *msg, uint32_t sip, uint32_t dip, 
    uint16_t sport, uint16_t dport, uint8_t *srcmac,
    uint8_t *dstmac, unsigned char *data, uint16_t total_len)
{
  // encode 构建udp包

  // 1. ethernet头,以太网头
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
  eth->ether_type = rte_htons(RTE_ETHER_TYPE_IPV4);

  // 2 iphdr 设置ip头
  // msg + sizeof(struct rte_ether_hdr) 相当于eth+1
  struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
  ip->version_ihl = 0x45;
  ip->type_of_service = 0; // ip的类型
  ip->total_length = rte_htons(total_len - sizeof(struct rte_ether_hdr)); // 转成网络字节序(大端序)
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64; // ttl = 64
  ip->next_proto_id = IPPROTO_UDP; // ip头要标识下一部分是什么协议
  ip->src_addr = sip;
  ip->dst_addr = dip;
  
  ip->hdr_checksum = 0; // 一开始置0防止checksum计算出错 
  ip->hdr_checksum = rte_ipv4_cksum(ip);

  // 3 udphdr 
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
  udp->src_port = g_src_port;
  udp->dst_port = g_dst_port;
  uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
  udp->dgram_len = rte_htons(udplen);
  // 数据放到udp头之下(udp payload),udp+1为即是以udp hdr为一单位偏移.实为偏移到udp hdr末尾
  rte_memcpy((uint8_t*)(udp+1), data, udplen);

  udp->dgram_cksum = 0;
  udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

  return 0;
}

// 发送数据包,参数分别为:内存buffer,payload,length(payload)长度
static struct rte_mbuf * ht_send_udp(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
    uint8_t *data, uint16_t length)
{

  // mempool --> mbuf(从mempool里获取数据buffer流)

  const unsigned total_len = length + 42; // 42是eth header + ip hdr + udp hdr

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "ht_send_udp: rte_pktmbuf_alloc\n");
  }

  mbuf->pkt_len = total_len; // 包的长度
  mbuf->data_len = total_len; // 数据的长度
  // 偏移uint8_t也就是一个字节一个字节处理
  uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

  ht_encode_udp_packet(pktdata, sip, dip, sport, dport, srcmac, 
      dstmac, data, total_len);

  return mbuf;
}

/* end of udp */

int ht_udp_out(struct rte_mempool *mbuf_pool) {
  struct udp_sock_fd *host;
  for (host = g_lhost; host != NULL; host = host->next) { // 遍历所有udp socket结点
    struct udp_payload *payload;
    int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&payload);
    if (nb_snd < 0) continue; // 没有数据,直接进入下一个.
    // 调试用
    char ip_buf[16] = {0};
    printf("udp_out ---> src: %s:%d \n", inet_ntoa2(payload->dip, ip_buf), rte_ntohs(payload->dport));
    // 如果arp table里面没有对应的mac地址
    uint8_t *dstmac = ht_get_dst_macaddr(payload->dip);
    if (dstmac == NULL) {
      // 先发arp request过去
      struct rte_mbuf *arpbuf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, g_default_arp_mac, 
        payload->sip, payload->dip);
      // 放入到send buffer中即可.发送在while循环中out buffer把packet出队列发送
      struct ring_buffer *ring = g_ring;
      rte_ring_mp_enqueue_burst(ring->send_ring, (void **)&arpbuf, 1, NULL);
      // 发送了arp request后再放入到udp send buffer里
      rte_ring_mp_enqueue(host->sndbuf, payload);
      
    } else {
      // arp table里有了直接构造udp包发送
      struct rte_mbuf *udpbuf = ht_send_udp(mbuf_pool, payload->sip, payload->dip, payload->sport, payload->dport,
        host->localmac, dstmac, payload->data, payload->length);

      // 发送直接放入到send buffer中即可
      struct ring_buffer *ring = g_ring;
      rte_ring_mp_enqueue_burst(ring->send_ring, (void **)&udpbuf, 1, NULL);
    }
  }

  return 0;
}

