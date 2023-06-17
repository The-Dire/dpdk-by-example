#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <netinet/in.h>

#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32

/* utils */
#define rte_htons rte_cpu_to_be_16
#define rte_htonl rte_cpu_to_be_32

#define rte_ntohs rte_be_to_cpu_16
#define rte_ntohl rte_be_to_cpu_32

/* IP network to ascii representation */
const char *
inet_ntop2(uint32_t ip)
{
  static char buf[16];
  const unsigned char *bytep;

  bytep = (const unsigned char *)&ip;
  sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
  return buf;
}

/*
 * IP network to ascii representation. To use
 * for multiple IP address convertion into the same call.
 */
char *
inet_ntoa2(uint32_t ip, char *buf)
{
  const unsigned char *bytep;

  bytep = (const unsigned char *)&ip;
  sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
  return buf;
}
/* end of utils */

int g_dpdk_port_id = 0; // 端口id
// 端口默认信息
static const struct rte_eth_conf port_conf_default = {
  .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
// 点分十进制ipv4地址变为数字ipv4地址
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
// 本地ip,即dpdk端口的ip(由于dpdk绕过了内核协议栈所以需要自己设置)
static uint32_t g_local_ip = MAKE_IPV4_ADDR(10, 66 ,24, 68);

// 六元组sip,dip,smac,dmac,sport,dport用来发送数据包,由于本项目只用于实验所以以全局变量形式
static uint32_t g_src_ip;
static uint32_t g_dst_ip;

static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];

static uint16_t g_src_port;
static uint16_t g_dst_port;
// 绑定网卡,初始化dpdk端口
static void ht_init_port(struct rte_mempool *mbuf_pool) {

  uint16_t nb_sys_ports= rte_eth_dev_count_avail(); // 1. 检测端口是否合法,是否设置
  if (nb_sys_ports == 0) {
    rte_exit(EXIT_FAILURE, "No Supported eth found\n");
  }
  // 2. 默认网卡信息获取
  struct rte_eth_dev_info dev_info;
  rte_eth_dev_info_get(g_dpdk_port_id, &dev_info);
  // 3. 配置rx队列和tx队列的数量
  const int num_rx_queues = 1; // 最多8个
  const int num_tx_queues = 1; // 写队列设置为1
  struct rte_eth_conf port_conf = port_conf_default;
  rte_eth_dev_configure(g_dpdk_port_id, num_rx_queues, num_tx_queues, &port_conf);

  // 4. 设置哪一个队列去接收数据, 1024是队列承载的数据包最大数量(程序员配置的)
  if (rte_eth_rx_queue_setup(g_dpdk_port_id, 0 , 1024, 
    rte_eth_dev_socket_id(g_dpdk_port_id),NULL, mbuf_pool) < 0) {
    rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
  }
  // 5. 设置tx队列,tx队列初始化
  struct rte_eth_txconf txq_conf = dev_info.default_txconf;
  txq_conf.offloads = port_conf.rxmode.offloads; // 上面的设置:即接收的包多大就发多大的数据包
  if (rte_eth_tx_queue_setup(g_dpdk_port_id, 0 , 1024, // 参数为: 对应网口,对应的队列,队列最大包数量,socket id,send的配置
    rte_eth_dev_socket_id(g_dpdk_port_id), &txq_conf) < 0) {
    rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
  }

  // 6. 其实是启动g_dpdk_port_id这个端口,有发送也有接收
  if (rte_eth_dev_start(g_dpdk_port_id) < 0 ) {
    rte_exit(EXIT_FAILURE, "Could not start\n");
  }
}

// 构建一个最简单的udp包,data参数是要发送的udp的payload
static int ht_encode_udp_packet(uint8_t *msg, unsigned char *data, uint16_t total_len)
{
  // encode 构建udp包

  // 1. ethernet头,以太网头
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->d_addr.addr_bytes, g_dst_mac, RTE_ETHER_ADDR_LEN);
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
  ip->src_addr = g_src_ip;
  ip->dst_addr = g_dst_ip;
  
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

  char ip_buf[16] = {0};
  printf(" --> src: %s:%d, ", inet_ntoa2(g_src_ip, ip_buf), rte_ntohs(g_src_port)); // 网络字节序大端序转为主机字节序小端序

  printf("dst: %s:%d\n", inet_ntoa2(g_dst_ip, ip_buf), rte_ntohs(g_dst_port));

  return 0;

}

// 发送数据包,参数分别为:内存buffer,payload,length(payload)长度
static struct rte_mbuf * ht_send_udp(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

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

  ht_encode_udp_packet(pktdata, data, total_len);

  return mbuf;
}

// 构建arp response包
static int ht_encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
  eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

  // 2 arp 
  struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
  arp->arp_hardware = htons(1);
  arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
  arp->arp_hlen = RTE_ETHER_ADDR_LEN; // 硬件地址长度
  arp->arp_plen = sizeof(uint32_t); // 软件地址长度
  arp->arp_opcode = htons(2); // 2为response,1为request
  rte_memcpy(arp->arp_data.arp_sha.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

  arp->arp_data.arp_sip = sip;
  arp->arp_data.arp_tip = dip;
  
  return 0;
}

// 发送arp response
static struct rte_mbuf *ht_send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
  // 14 + 28, eth头14字节,arp头28字节
  const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "ht_send_arp: rte_pktmbuf_alloc\n");
  }

  mbuf->pkt_len = total_length;
  mbuf->data_len = total_length;

  uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
  ht_encode_arp_pkt(pkt_data, dst_mac, sip, dip);

  return mbuf;
}


int main(int argc, char *argv[]) {
  // dpdk环境初始化,巨页,内存,cpu亲和等的设置
  if (rte_eal_init(argc, argv) < 0) {
    rte_exit(EXIT_FAILURE, "Error with EAL init\n");
  }
  // 构造内存池,收发的数据都要放入其中
  struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
    0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (mbuf_pool == NULL) {
    rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
  }

  ht_init_port(mbuf_pool);
  // 获取网卡mac地址,用于ng_encode_udp_pkt函数中组建ether头
  rte_eth_macaddr_get(g_dpdk_port_id, (struct rte_ether_addr *)g_src_mac);

  while (1) {
    struct rte_mbuf *mbufs[BURST_SIZE];
    // 第一个参数为端口id(对应网络适配器),第二个参数是指定对应队列,第三个参数是mbufs从内存池里分配的数据
    // 接收数据包,最大数据包数量在ng_init_port中rte_eth_rx_queue_setup设置,设置为128
    unsigned num_recvd = rte_eth_rx_burst(g_dpdk_port_id, 0, mbufs, BURST_SIZE);
    if (num_recvd > BURST_SIZE) {
      rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
    }
    // 操作数据包
    unsigned i = 0;
    for (i = 0;i < num_recvd;i ++) {
      // 从mbufs[i]内存中取出数据包,先解析Ethernet头
      struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
      
      // 对端发送的是arp协议,对arp进行解析
      if (ehdr->ether_type == rte_htons(RTE_ETHER_TYPE_ARP)) {
        // 获取arp头
        struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbufs[i], 
            struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
        
        char ip_buf[16] = {0};
        printf("arp ---> src: %s ", inet_ntoa2(arp_hdr->arp_data.arp_tip, ip_buf));
        printf(" local: %s \n", inet_ntoa2(g_local_ip, ip_buf));
        // 由于arp request是广播,判断目标地址相同才返回arp response
        if (arp_hdr->arp_data.arp_tip == g_local_ip) {
          // 接收到arp request包后返回arp response。注:request里的源ip是response里的目的ip
          struct rte_mbuf *arp_buf = ht_send_arp(mbuf_pool, arp_hdr->arp_data.arp_sha.addr_bytes, 
            arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip);
          rte_eth_tx_burst(g_dpdk_port_id, 0, &arp_buf, 1);
          rte_pktmbuf_free(arp_buf);
          rte_pktmbuf_free(mbufs[i]);
        }
        continue;
      }
      
      if (ehdr->ether_type != rte_htons(RTE_ETHER_TYPE_IPV4)) { // 判断是否是ip协议
        continue; // 不是ip协议不做处理
      }
      // 解析ip协议头部
      struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
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
        struct rte_mbuf *txbuf = ht_send_udp(mbuf_pool, (uint8_t *)(udphdr+1), length);
        rte_eth_tx_burst(g_dpdk_port_id, 0, &txbuf, 1);// rte_eth_rx_burst发送数据
        rte_pktmbuf_free(txbuf); // 发送用的mbuf同样放回到内存池中

        rte_pktmbuf_free(mbufs[i]); // 放回内存池
      }
    }
  }
}
