#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <rte_malloc.h>
#include <rte_timer.h> // 定时器,用来定时发送广播 arp

#include <rte_ring.h> // dpdk 队列库

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "arp.h"

#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32
#define RING_SIZE	1024
// 每隔TIMER_RESOLUTION_CYCLES广播arp(发送广播 arp)
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6 

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
// 链表操作宏
#define LL_ADD(item, list) do {		\
  item->prev = NULL;				\
  item->next = list;				\
  if (list != NULL) list->prev = item; \
  list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
  if (item->prev != NULL) item->prev->next = item->next;	\
  if (item->next != NULL) item->next->prev = item->prev;	\
  if (list == item) list = item->next;	\
  item->prev = item->next = NULL;			\
} while(0)
/* end of utils */

int g_dpdk_port_id = 0; // 端口id
// 端口默认信息
static const struct rte_eth_conf port_conf_default = {
  .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
// 点分十进制ipv4地址变为数字ipv4地址
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
// 本地ip,即dpdk端口的ip(由于dpdk绕过了内核协议栈所以需要自己设置)
static uint32_t g_local_ip = MAKE_IPV4_ADDR(10, 66 ,24, 108);

// 六元组sip,dip,smac,dmac,sport,dport用来发送数据包,由于本项目只用于实验所以以全局变量形式
static uint32_t g_src_ip;
static uint32_t g_dst_ip;

static uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
static uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];

static uint16_t g_src_port;
static uint16_t g_dst_port;

static uint8_t g_default_arp_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// 两个ring队列,一个收包队列收包后存入用来解析协议
// 一个发包队列待发的包存入
// 这样做收发包可以分别通过两个不同的核心进行
struct ring_buffer {
  struct rte_ring *recv_ring;
  struct rte_ring *send_ring;
};

// 只生成一个全局变量来管理ring
struct ring_buffer *g_ring = NULL;
// main函数中调用初始化全局队列
void init_global_ring() {
  if (g_ring == NULL) {
    g_ring = rte_malloc("recv/send ring", sizeof(struct ring_buffer), 0);
    memset(g_ring, 0, sizeof(struct ring_buffer));
  }
}

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

/* arp组包发包相关模块 */
// 构建arp response包. 自定义opcode 1为request,2为response
static int ht_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, g_src_mac, RTE_ETHER_ADDR_LEN);
  // 如果目的mac与g_default_arp_mac地址一致,还要特殊处理以太网头mac地址字段
  if (!strncmp((const char *)dst_mac, (const char *)g_default_arp_mac, RTE_ETHER_ADDR_LEN)) {
    uint8_t mac[RTE_ETHER_ADDR_LEN] = {0x0};
    rte_memcpy(eth->d_addr.addr_bytes, mac, RTE_ETHER_ADDR_LEN);
  } else {
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
static struct rte_mbuf *ht_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip) {
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
/* end of arp */

/* icmp组包发包相关模块 */
static uint16_t ht_checksum(void *addr, int count) {
  
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

static int ht_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
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

static struct rte_mbuf *ht_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
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
/* end of icmp */

void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

/* begin of free arp request send */
void arp_request_timer_callback(__attribute__((unused)) struct rte_timer *tim,
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
    // printf("arp ---> src: %s ----- %d\n", inet_ntoa2(dst_ip, ip_buf), i);

    struct rte_mbuf* arp_buf = NULL;
    uint8_t *dst_mac = ht_get_dst_macaddr(dst_ip);
    // 如果arp table里面没有对应dst ip地址,那么arp hdr和ether hdr中的dmac字段自己构造发送.
    if (dst_mac == NULL) {
			// arp hdr --> mac : FF:FF:FF:FF:FF:FF
			// ether hdr --> mac : 00:00:00:00:00:00
			arp_buf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, g_default_arp_mac, g_local_ip, dst_ip); 
    } else { // 常规的arp request发送
      arp_buf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dst_mac, g_local_ip, dst_ip);
    }

    //rte_eth_tx_burst(g_dpdk_port_id, 0, &arp_buf, 1);
    //rte_pktmbuf_free(arp_buf);
    // 待发送的arp包存入队列中
    rte_ring_mp_enqueue_burst(send_ring, (void**)&arp_buf, 1, NULL);
  }
}
/* end of free arp */

/* udp and tcp structure*/
// 用来存储所有的tcp stream 是一个双向链表
#define DEFAULT_FD_NUM	3

#define MAX_FD_COUNT 1024

static unsigned char fd_table[MAX_FD_COUNT] = {0};
// udp
struct udp_sock_fd {
  int fd;
  //unsigned int status;
  uint32_t localip; // ip --> mac
  uint8_t localmac[RTE_ETHER_ADDR_LEN]; // 源mac地址,与ip地址要一一对应
  uint16_t localport;

  uint8_t protocol;

  struct rte_ring *sndbuf; // sendbuffer
  struct rte_ring *rcvbuf; // recvbuffer
  // 如果启动多个udp server,需要链表记录
  struct udp_sock_fd *prev;
  struct udp_sock_fd *next;

  pthread_cond_t cond;
  pthread_mutex_t mutex;
};

static struct udp_sock_fd *lhost = NULL;

// 因为arp协议存在知道ip就能查到对应的mac,所以该结构体没有mac字段
struct offload { // 用来组装udp数据包
  uint32_t sip; // 源ip
  uint32_t dip; // 目的ip

  uint16_t sport; // 源端口
  uint16_t dport; // 目的端口

  int protocol;	// 协议

  unsigned char *data; // 数据段
  uint16_t length;	 // 长度
}; 

// tcp
#define TCP_OPTION_LENGTH   10

#define TCP_MAX_SEQ         4294967295 // 2的32次方

#define TCP_INITIAL_WINDOW  14600

typedef enum _HT_TCP_STATUS {
  HT_TCP_STATUS_CLOSED = 0,
  HT_TCP_STATUS_LISTEN,
  HT_TCP_STATUS_SYN_RCVD,
  HT_TCP_STATUS_SYN_SENT,
  HT_TCP_STATUS_ESTABLISHED,
  // 6个断开时所需的状态
  HT_TCP_STATUS_FIN_WAIT_1,
  HT_TCP_STATUS_FIN_WAIT_2,
  HT_TCP_STATUS_CLOSING,
  HT_TCP_STATUS_TIME_WAIT,

  HT_TCP_STATUS_CLOSE_WAIT,
  HT_TCP_STATUS_LAST_ACK
} HT_TCP_STATUS;

// tcp每个连接的管理结构体
struct ht_tcp_stream { // tcp控制块
  int fd; // 文件描述符

  uint32_t sip; // 源ip
  uint32_t dip; // 目的ip

  uint16_t sport; // 源端口
  uint16_t dport; // 目的端口

  uint16_t proto; // 协议
  // mac地址,发数据的时候装填
  uint8_t localmac[RTE_ETHER_ADDR_LEN];
  // ack和syn number
  uint32_t snd_nxt; // seq number
  uint32_t rcv_nxt; // ack number
  // tcp状态
  HT_TCP_STATUS status;

  // 发送和接收ring
  struct rte_ring *sndbuf;
  struct rte_ring *rcvbuf;
  // tcp控制块前驱和后继
  struct ht_tcp_stream *prev;
  struct ht_tcp_stream *next;

  pthread_cond_t cond;
  pthread_mutex_t mutex;
};

struct ht_tcp_table {
  int count;
  struct ht_tcp_stream *tcb_set;
};

// tcp包数据帧结构(类似于rte_tcp_hdr)
struct ht_tcp_fragment {
  uint16_t sport;    // 源端口
  uint16_t dport;    // 目的端口
  uint32_t seqnum;   // seq number
  uint32_t acknum;   // ack number
  uint8_t hdrlen_off;// 首部长度
  uint8_t tcp_flags; // tcp标志
  uint16_t windows;  // 窗口大小
  uint16_t checksum; // 校验和
  uint16_t tcp_urp;  // 紧急指针
  // tcp option选项处理
  uint32_t optlen;
  uint32_t option[TCP_OPTION_LENGTH];

  unsigned char *data;
  int length;
};

static struct ht_tcp_table *g_tcp_tb = NULL;
/* end of structure*/


/* udp socket */
// 生成fd
static int get_fd_frombitmap(void) {
  int fd = DEFAULT_FD_NUM;
  for ( ; fd < MAX_FD_COUNT; fd++) {
    if ((fd_table[fd/8] & (0x1 << (fd % 8))) == 0) {
      fd_table[fd/8] |= (0x1 << (fd % 8));
      return fd;
    }
  }
  return fd;
}

static int set_fd_frombitmap(int fd) {
  if (fd >= MAX_FD_COUNT) return -1;
  fd_table[fd/8] &= ~(0x1 << (fd % 8));
  return 0;
}

static struct ht_tcp_stream *get_accept_tcb(uint16_t dport) {
  struct ht_tcp_stream *apt;
  struct ht_tcp_table *table = g_tcp_tb;
  for (apt = table->tcb_set; apt != NULL;apt = apt->next) {
    if (dport == apt->dport && apt->fd == -1) {
      return apt;
    }
  }

  return NULL;
}

// 通过socket id找到对应的socket结构体
static void * get_hostinfo_fromfd(int sockfd) {
  struct udp_sock_fd *host;
  for (host = lhost; host != NULL;host = host->next) {
    if (sockfd == host->fd) {
      return host;
    }
  }

  // 找完udp,如果没有还需要再找tcp
  struct ht_tcp_stream *stream = NULL;
  struct ht_tcp_table *table = g_tcp_tb;
  for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
    if (sockfd == stream->fd)
      return stream;
  }

  return NULL;
}
// 通过ip和post找到对应socket去接收或者发送数据包
static struct udp_sock_fd * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto) {
  struct udp_sock_fd *host;
  for (host = lhost; host != NULL;host = host->next) {
    if (dip == host->localip && port == host->localport && proto == host->protocol) {
      return host;
    }
  }
  return NULL;
}

// udp包的处理(从旧的pkt_process中剥离出来).只做数据包的解析.
// 1.解析数据,填充offload 2.放入到recv buffer里面
static int udp_process(struct rte_mbuf *udpmbuf) {
  // ipv4头和udp头获取
  struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, 
        sizeof(struct rte_ether_hdr));
  struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

  // 调试用
  char ip[16] = {0};
  printf("udp_process ---> src: %s:%d \n", inet_ntoa2(iphdr->src_addr, ip), rte_ntohs(udphdr->src_port));
  // 根据ip和port获取udp_sock_fd结构体
  struct udp_sock_fd *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
  if (host == NULL) {
    rte_pktmbuf_free(udpmbuf);
    return -3;
  } 

  struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
  if (ol == NULL) {
    rte_pktmbuf_free(udpmbuf);
    return -1;
  }

  ol->dip = iphdr->dst_addr;
  ol->sip = iphdr->src_addr;
  ol->sport = udphdr->src_port;
  ol->dport = udphdr->dst_port;

  ol->protocol = IPPROTO_UDP;
  ol->length = rte_ntohs(udphdr->dgram_len);
  // 数据段长度,总长度 - udp首部长度
  ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
  if (ol->data == NULL) {
    rte_pktmbuf_free(udpmbuf);
    rte_free(ol);
    return -2;
  }
  rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr)); // 关键步骤,接收到的udp数据段要赋值给offload

  rte_ring_mp_enqueue(host->rcvbuf, ol); // recv buffer

  pthread_mutex_lock(&host->mutex);
  pthread_cond_signal(&host->cond);
  pthread_mutex_unlock(&host->mutex);

  rte_pktmbuf_free(udpmbuf);

  return 0;
}

static int ht_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
  uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
  unsigned char *data, uint16_t total_len) {
  // encode 
  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
  eth->ether_type = rte_htons(RTE_ETHER_TYPE_IPV4);

  // 2 iphdr 
  struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
  ip->version_ihl = 0x45;
  ip->type_of_service = 0;
  ip->total_length = rte_htons(total_len - sizeof(struct rte_ether_hdr));
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64; // ttl = 64
  ip->next_proto_id = IPPROTO_UDP;
  ip->src_addr = sip;
  ip->dst_addr = dip;

  ip->hdr_checksum = 0;
  ip->hdr_checksum = rte_ipv4_cksum(ip);
  // 3 udphdr 
  struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
  udp->src_port = sport;
  udp->dst_port = dport;
  uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
  udp->dgram_len = rte_htons(udplen);

  rte_memcpy((uint8_t*)(udp+1), data, udplen);

  udp->dgram_cksum = 0;
  udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

  return 0;
}


static struct rte_mbuf * ht_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
  uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
  uint8_t *data, uint16_t length) {

  // mempool --> mbuf
  const unsigned total_len = length + 42;

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
  }
  mbuf->pkt_len = total_len;
  mbuf->data_len = total_len;

  uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

  ht_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
    data, total_len);

  return mbuf;
}


// offload --> mbuf
static int udp_out(struct rte_mempool *mbuf_pool) {
  struct udp_sock_fd *host;
  for (host = lhost; host != NULL; host = host->next) { // 遍历所有udp socket结点
    struct offload *ol;
    int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
    if (nb_snd < 0) continue; // 没有数据,直接进入下一个.
    // 调试用
    char ip[16] = {0};
    printf("udp_out ---> src: %s:%d \n", inet_ntoa2(ol->dip, ip), rte_ntohs(ol->dport));
    // 如果arp table里面没有对应的mac地址
    uint8_t *dstmac = ht_get_dst_macaddr(ol->dip);
    if (dstmac == NULL) {
      // 先发arp request过去
      struct rte_mbuf *arpbuf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, g_default_arp_mac, 
        ol->sip, ol->dip);
      // 放入到send buffer中即可.发送在while循环中send buffer把packet出队列发送
      struct ring_buffer *ring = g_ring;
      rte_ring_mp_enqueue_burst(ring->send_ring, (void **)&arpbuf, 1, NULL);
      // 发送了arp request后再放入到send buffer里
      rte_ring_mp_enqueue(host->sndbuf, ol);
    } else {
      // arp table里有了直接构造udp包发送
      struct rte_mbuf *udpbuf = ht_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
        host->localmac, dstmac, ol->data, ol->length);
      // 发送直接放入到send buffer中即可
      struct ring_buffer *ring = g_ring;
      rte_ring_mp_enqueue_burst(ring->send_ring, (void **)&udpbuf, 1, NULL);
    }
  }

  return 0;
}

// 实现的基本的socket api
static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {
  int fd = get_fd_frombitmap(); // 1.文件描述符fd生成

  // 通过type赋值要传输的协议
  // udp socket创建
  if (type == SOCK_DGRAM) {
    // 2.分配一个host
    struct udp_sock_fd *host = rte_malloc("udp_sock_fd", sizeof(struct udp_sock_fd), 0);
    if (host == NULL) {
      return -1;
    }
    memset(host, 0, sizeof(struct udp_sock_fd));
    // 文件描述符赋值
    host->fd = fd;
    host->protocol = IPPROTO_UDP;
    // 构建recv buffer和send buffer
    host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->rcvbuf == NULL) {
      rte_free(host);
      return -1;
    }

    host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (host->sndbuf == NULL) {
      rte_ring_free(host->rcvbuf);
      rte_free(host);
      return -1;
    }
    // 用于实现阻塞,在recvfrom里面调用
    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));
    // 3.该host(socket)添加到socket链表中
    LL_ADD(host, lhost);
  }
  else if (type == SOCK_STREAM) {
    struct ht_tcp_stream *stream = rte_malloc("ht_tcp_stream", sizeof(struct ht_tcp_stream), 0);
    if (stream == NULL) {
      return -1;
    }

    memset(stream, 0, sizeof(struct ht_tcp_stream));

    stream->fd = fd;
    stream->proto = IPPROTO_TCP;
    stream->next = stream->prev = NULL;

    stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stream->rcvbuf == NULL) {
      rte_free(stream);
      return -1;
    }

    stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (stream->sndbuf == NULL) {
      rte_ring_free(stream->rcvbuf);
      rte_free(stream);
      return -1;
    }

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    struct ht_tcp_table *table = g_tcp_tb;
    LL_ADD(stream, table->tcb_set);
  }
  return fd;
}
// 1.通过socket id找到hostinfo 2. 设置相应的ip地址
static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

  struct udp_sock_fd *hostinfo =  get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct udp_sock_fd *host = (struct udp_sock_fd *)hostinfo;
  if (host->protocol == IPPROTO_UDP) {
    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    host->localport = laddr->sin_port;
    rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(host->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);
  }
  else {
    struct ht_tcp_stream *stream = (struct ht_tcp_stream *)hostinfo;
    const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
    stream->dport = laddr->sin_port;
    rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(stream->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);
    stream->status = HT_TCP_STATUS_CLOSED; // 初始状态位CLOSED,listen后状态为LISTEN
  }

  return 0;
}
// only for tcp
static int nlisten(int sockfd, __attribute__((unused)) int backlog) { //
  void *hostinfo =  get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ht_tcp_stream *stream = (struct ht_tcp_stream *)hostinfo;
  if (stream->proto == IPPROTO_TCP) {
    stream->status = HT_TCP_STATUS_LISTEN;
  }

  return 0;
}

static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {
  void *hostinfo =  get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ht_tcp_stream *stream = (struct ht_tcp_stream *)hostinfo;
  if (stream->proto == IPPROTO_TCP) {
    struct ht_tcp_stream *apt = NULL;
    pthread_mutex_lock(&stream->mutex);
    while((apt = get_accept_tcb(stream->dport)) == NULL) {
      pthread_cond_wait(&stream->cond, &stream->mutex);
    } 
    pthread_mutex_unlock(&stream->mutex);

    apt->fd = get_fd_frombitmap();

    struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
    saddr->sin_port = apt->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

    return apt->fd;
  }

  return -1;
}


static ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) {
  ssize_t length = 0;
  void *hostinfo =  get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ht_tcp_stream *stream = (struct ht_tcp_stream *)hostinfo;
  if (stream->proto == IPPROTO_TCP) {
    struct ht_tcp_fragment *fragment = rte_malloc("ht_tcp_fragment", sizeof(struct ht_tcp_fragment), 0);
    if (fragment == NULL) {
      return -2;
    }

    memset(fragment, 0, sizeof(struct ht_tcp_fragment));

    fragment->dport = stream->sport;
    fragment->sport = stream->dport;

    fragment->acknum = stream->rcv_nxt;
    fragment->seqnum = stream->snd_nxt;

    fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
    fragment->windows = TCP_INITIAL_WINDOW;
    fragment->hdrlen_off = 0x50;

    fragment->data = rte_malloc("unsigned char *", len+1, 0);
    if (fragment->data == NULL) {
      rte_free(fragment);
      return -1;
    }
    memset(fragment->data, 0, len+1);

    rte_memcpy(fragment->data, buf, len);
    fragment->length = len;
    length = fragment->length;

    // int nb_snd = 0;
    rte_ring_mp_enqueue(stream->sndbuf, fragment);
  }

  return length;
}

// recv 32
// recv 
static ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
  ssize_t length = 0;

  void *hostinfo =  get_hostinfo_fromfd(sockfd);
  if (hostinfo == NULL) return -1;

  struct ht_tcp_stream *stream = (struct ht_tcp_stream *)hostinfo;
  if (stream->proto == IPPROTO_TCP) {

    struct ht_tcp_fragment *fragment = NULL;
    int nb_rcv = 0;

    printf("rte_ring_mc_dequeue before\n");
    pthread_mutex_lock(&stream->mutex);
    while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
      pthread_cond_wait(&stream->cond, &stream->mutex);
    }
    pthread_mutex_unlock(&stream->mutex);
    printf("rte_ring_mc_dequeue after\n");

    if (fragment->length > len) {
      rte_memcpy(buf, fragment->data, len);
      uint32_t i = 0;
      for(i = 0;i < fragment->length-len;i ++) {
        fragment->data[i] = fragment->data[len+i];
      }
      fragment->length = fragment->length-len;
      length = fragment->length;

      rte_ring_mp_enqueue(stream->rcvbuf, fragment);
    }
    else if (fragment->length == 0) {
      rte_free(fragment);
      return 0;
    }
    else {
      rte_memcpy(buf, fragment->data, fragment->length);
      length = fragment->length;

      rte_free(fragment->data);
      fragment->data = NULL;

      rte_free(fragment);
    }
  }

  return length;
}
// only for tcp end

// only for udp
static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {
  // 1.判断host是否存在
  struct udp_sock_fd *host =  get_hostinfo_fromfd(sockfd);
  if (host == NULL) return -1;

  struct offload *ol = NULL;
  unsigned char *ptr = NULL;

  struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
  int nb = -1;
  // 2.阻塞等待地接收数据
  // 加入来锁为阻塞地接收数据
  pthread_mutex_lock(&host->mutex);
  // recv buffer里面接收一个数据包(把buffer里面的值放入到ol中)
  while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
    pthread_cond_wait(&host->cond, &host->mutex);
  }
  pthread_mutex_unlock(&host->mutex);
  // 填充sockaddr_in地址
  saddr->sin_port = ol->sport;
  rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));
  // 3. 数据放入到buffer中
  if (len < ol->length) { // 出现错误,长度小于包长度,重新分配buf大小
    rte_memcpy(buf, ol->data, len);

    ptr = rte_malloc("unsigned char *", ol->length-len, 0);
    rte_memcpy(ptr, ol->data+len, ol->length-len);

    ol->length -= len;
    rte_free(ol->data);
    ol->data = ptr;
    
    rte_ring_mp_enqueue(host->rcvbuf, ol); // 放入到recv buffer中
    return len;
  } else {

    rte_memcpy(buf, ol->data, ol->length); // 直接拷贝到buf中
    rte_free(ol->data);
    rte_free(ol);
    return ol->length;
  }
}
// 1. 准备一个offload数据包结构 2.放入到send buffer中
static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {
  struct udp_sock_fd *host =  get_hostinfo_fromfd(sockfd);
  if (host == NULL) return -1;

  const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

  struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
  if (ol == NULL) return -1;

  ol->dip = daddr->sin_addr.s_addr;
  ol->dport = daddr->sin_port;
  ol->sip = host->localip;
  ol->sport = host->localport;
  ol->length = len;

  char ip[16] = {0};
  printf("nsendto ---> src: %s:%d \n", inet_ntoa2(ol->dip, ip), rte_ntohs(ol->dport));
  ol->data = rte_malloc("unsigned char *", len, 0);
  if (ol->data == NULL) {
    rte_free(ol);
    return -1;
  }

  rte_memcpy(ol->data, buf, len);
  rte_ring_mp_enqueue(host->sndbuf, ol);

  return len;
}
// end of udp only

static int nclose(int fd) {
  void *hostinfo = get_hostinfo_fromfd(fd);
  if (hostinfo == NULL) return -1;
  struct udp_sock_fd *host =  get_hostinfo_fromfd(fd);

  if (host->protocol == IPPROTO_UDP) {
    // 链表中移除掉该udp_sock_fd结构
    LL_REMOVE(host, lhost);
    // 释放recv buffer和send buffer
    if (host->rcvbuf) {
      rte_ring_free(host->rcvbuf);
    }
    if (host->sndbuf) {
      rte_ring_free(host->sndbuf);
    }

    rte_free(host);

    set_fd_frombitmap(fd);
  }
  else if (host->protocol == IPPROTO_TCP) {
    struct ht_tcp_stream *stream = (struct ht_tcp_stream*)hostinfo;

    if (stream->status != HT_TCP_STATUS_LISTEN) {
      
      struct ht_tcp_fragment *fragment = rte_malloc("ht_tcp_fragment", sizeof(struct ht_tcp_fragment), 0);
      if (fragment == NULL) return -1;

      printf("nclose --> enter last ack\n");
      fragment->data = NULL;
      fragment->length = 0;
      fragment->sport = stream->dport;
      fragment->dport = stream->sport;

      fragment->seqnum = stream->snd_nxt;
      fragment->acknum = stream->rcv_nxt;

      fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
      fragment->windows = TCP_INITIAL_WINDOW;
      fragment->hdrlen_off = 0x50;

      rte_ring_mp_enqueue(stream->sndbuf, fragment);
      stream->status = HT_TCP_STATUS_LAST_ACK;

      set_fd_frombitmap(fd);
    }
    else { // nsocket
      struct ht_tcp_table *table = g_tcp_tb;
      LL_REMOVE(stream, table->tcb_set);	

      rte_free(stream);
    }
  }
}

#define UDP_APP_RECV_BUFFER_SIZE	128

static int udp_server_entry(__attribute__((unused))  void *arg) {
  int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
  if (connfd == -1) {
    printf("sockfd failed\n");
    return -1;
  } 

  struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
  memset(&localaddr, 0, sizeof(struct sockaddr_in));

  localaddr.sin_port = rte_htons(8889);
  localaddr.sin_family = AF_INET;
  localaddr.sin_addr.s_addr = inet_addr("10.66.24.108"); // 0.0.0.0


  nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

  char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
  socklen_t addrlen = sizeof(clientaddr);
  while (1) {

    if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, 
      (struct sockaddr*)&clientaddr, &addrlen) < 0) {
      continue;
    } else {
      printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), 
        rte_ntohs(clientaddr.sin_port), buffer);
      nsendto(connfd, buffer, strlen(buffer), 0, 
        (struct sockaddr*)&clientaddr, sizeof(clientaddr));
    }

  }

  nclose(connfd);
}
/* end of udp socket */

/* tcp socket */
// 初始化tcp表
void init_tcp_table() {
  if (g_tcp_tb == NULL) {
    g_tcp_tb = rte_malloc("ht_tcp_table", sizeof(struct ht_tcp_table), 0);
    memset(g_tcp_tb, 0, sizeof(struct ht_tcp_table));
  }
}

// 查找tcp stream(连接)
struct ht_tcp_stream * ht_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) { // proto就是tcp
  // 获取tcp table
  struct ht_tcp_table *table = g_tcp_tb;
  struct ht_tcp_stream *iter;

  for (iter = table->tcb_set;iter != NULL; iter = iter->next) {
    // 通过四元组查找到具体连接
    if (iter->sip == sip && iter->dip == dip && 
      iter->sport == sport && iter->dport == dport) {
      return iter;
    }
  }
  // 连接已经建立
  for (iter = table->tcb_set; iter != NULL; iter->next) {
    if (iter->dport == dport && iter->status == HT_TCP_STATUS_LISTEN) { // listen
      return iter;
    }
  }
  return NULL;
}

struct ht_tcp_stream *ht_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
  // tcp --> status(需要设置初始状态)
  struct ht_tcp_stream *stream = rte_malloc("ht_tcp_stream", sizeof(struct ht_tcp_stream), 0);
  if (stream == NULL) return NULL;
  // 初始化stream
  stream->sip = sip;
  stream->dip = dip;
  stream->sport = sport;
  stream->dport = dport;
  stream->proto = IPPROTO_TCP;
  stream->fd = -1;
  // 这里状态设置为LISTENE状态.在服务器的时候初始状态为LISTEN.客户端则为CLOSE.这里为了简化没有做区分
  stream->status = HT_TCP_STATUS_LISTEN;

  printf("ht_tcp_stream_create\n");
  // 该tcp stream的recv buffer和send buffer初始化
  stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
  stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);
  // seq num 该值是一个随机值
  uint32_t next_seed = time(NULL);
  stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
  // 绑定local mac
  rte_memcpy(stream->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);

  pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
  rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

  pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
  rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

  // listen后再把当前创建的stream加入到tcp table中
  // struct ht_tcp_table *table = g_tcp_tb;
  // LL_ADD(stream, table->tcb_set);

  return stream;
}

static int ht_tcp_handle_listen(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG)  { // tcp头带有SYN FLAG时,要进行listean状态处理
    // tcp可能重复发送,仅处理一次
    if (stream->status == HT_TCP_STATUS_LISTEN) {
      struct ht_tcp_table *table = g_tcp_tb;
      struct ht_tcp_stream *stream = ht_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
      LL_ADD(stream, table->tcb_set);

      // 创建一个tcp数据包
      struct ht_tcp_fragment *fragment = rte_malloc("ht_tcp_fragment", sizeof(struct ht_tcp_fragment), 0);
      if (fragment == NULL) return -1; // 分配失败
      memset(fragment, 0, sizeof(struct ht_tcp_fragment));
      // 填充fragment即填充tcp数据包,服务器和客户端的dst和src是相反的
      fragment->sport = tcphdr->dst_port;
      fragment->dport = tcphdr->src_port;

      char src_ip[16] = {0};
      printf("tcp ---> src: %s:%d ", inet_ntoa2(stream->sip, src_ip), rte_ntohs(tcphdr->src_port));

      char dst_ip[16] = {0};
      printf("  ---> dst: %s:%d \n", inet_ntoa2(stream->dip, dst_ip), rte_ntohs(tcphdr->dst_port));
      // seq num等于创建stream里的seq值
      fragment->seqnum = stream->snd_nxt;
      fragment->acknum = rte_ntohl(tcphdr->sent_seq) + 1; // 大端序网络字节序要转为小端字节序
      stream->rcv_nxt = fragment->acknum;

      fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
      fragment->windows = TCP_INITIAL_WINDOW; // 这个值是linux内核中的值
      fragment->hdrlen_off = 0x50;	// 首部长度 20字节
      
      fragment->data = NULL;
      fragment->length = 0;
      // 把tcp数据包放入到该stream里的send buffer里
      rte_ring_mp_enqueue(stream->sndbuf, fragment);
      // 状态修改为SYN_RECV
      stream->status = HT_TCP_STATUS_SYN_RCVD;
    }

  }

  return 0;
}
// syn_recv状态的处理.
static int ht_tcp_handle_syn_rcvd(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) { // tcp标志中存在ACK标志
    // 避免重复的包
    if (stream->status == HT_TCP_STATUS_SYN_RCVD) {
      // 获取收到的ack的值
      uint32_t acknum = rte_ntohl(tcphdr->recv_ack);
      if (acknum == stream->snd_nxt + 1) {
        // to do
      }
      stream->status = HT_TCP_STATUS_ESTABLISHED; // 改变tcp状态为ESTABLISHED

      // accept
      struct ht_tcp_stream *listener = ht_tcp_stream_search(0, 0, 0, stream->dport);
      if (listener == NULL)
        rte_exit(EXIT_FAILURE, "ht_tcp_stream_search failed\n");
      
      pthread_mutex_lock(&listener->mutex);
      pthread_cond_signal(&listener->cond);
      pthread_mutex_unlock(&listener->mutex);
    }
  }
  return 0;
}

static int ht_tcp_enqueue_recvbuffer(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
  // recv buffer
  struct ht_tcp_fragment *rfragment = rte_malloc("ht_tcp_fragment", sizeof(struct ht_tcp_fragment), 0);
  if (rfragment == NULL) return -1;
  memset(rfragment, 0, sizeof(struct ht_tcp_fragment));

  rfragment->dport = rte_ntohs(tcphdr->dst_port);
  rfragment->sport = rte_ntohs(tcphdr->src_port);

  uint8_t hdrlen = tcphdr->data_off >> 4;
  int payloadlen = tcplen - hdrlen * 4;
  if (payloadlen > 0) {
    uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

    rfragment->data = rte_malloc("unsigned char *", payloadlen+1, 0);
    if (rfragment->data == NULL) {
      rte_free(rfragment);
      return -1;
    }
    memset(rfragment->data, 0, payloadlen+1);

    rte_memcpy(rfragment->data, payload, payloadlen);
    rfragment->length = payloadlen;
  }
  else if (payloadlen == 0) {
    rfragment->length = 0;
    rfragment->data = NULL;
  }
  rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

  pthread_mutex_lock(&stream->mutex);
  pthread_cond_signal(&stream->cond);
  pthread_mutex_unlock(&stream->mutex);

  return 0;
}

static int ht_tcp_send_ackpkt(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
  struct ht_tcp_fragment *ackfrag = rte_malloc("ht_tcp_fragment", sizeof(struct ht_tcp_fragment), 0);
  if (ackfrag == NULL) return -1;
  memset(ackfrag, 0, sizeof(struct ht_tcp_fragment));

  ackfrag->dport = tcphdr->src_port;
  ackfrag->sport = tcphdr->dst_port;

  // remote
  printf("ht_tcp_send_ackpkt: %d, %d\n", stream->rcv_nxt, rte_ntohs(tcphdr->sent_seq));

  ackfrag->acknum = stream->rcv_nxt;
  ackfrag->seqnum = stream->snd_nxt;

  ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
  ackfrag->windows = TCP_INITIAL_WINDOW;
  ackfrag->hdrlen_off = 0x50;
  ackfrag->data = NULL;
  ackfrag->length = 0;

  rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

  return 0;
}
// 建立连接后处理
static int ht_tcp_handle_established(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen) {
  if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
    // todo
  }

  if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) { //
    // recv buffer
    ht_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);

    uint8_t hdrlen = tcphdr->data_off >> 4;
    int payloadlen = tcplen - hdrlen * 4;
    
    stream->rcv_nxt = stream->rcv_nxt + payloadlen;
    stream->snd_nxt = rte_ntohl(tcphdr->recv_ack);
    // Push状态需要发包
    ht_tcp_send_ackpkt(stream, tcphdr);
  }
  if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
    // ack不处理
  }
  if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {
    // fin需要发终止包
    stream->status = HT_TCP_STATUS_CLOSE_WAIT;
    ht_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);

    // send ack ptk
    stream->rcv_nxt = stream->rcv_nxt + 1;
    stream->snd_nxt = rte_ntohl(tcphdr->recv_ack);
    
    ht_tcp_send_ackpkt(stream, tcphdr);
  }

  return 0;
}

static int ht_tcp_handle_close_wait(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) { //
    if (stream->status == HT_TCP_STATUS_CLOSE_WAIT) {
      // todo
    }
  }

  return 0;
}

static int ht_tcp_handle_last_ack(struct ht_tcp_stream *stream, struct rte_tcp_hdr *tcphdr) {
  if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
    if (stream->status == HT_TCP_STATUS_LAST_ACK) {
      stream->status = HT_TCP_STATUS_CLOSED;
      printf("ht_tcp_handle_last_ack\n");
      
      struct ht_tcp_table *table = g_tcp_tb;
      LL_REMOVE(stream, table->tcb_set);

      rte_ring_free(stream->sndbuf);
      rte_ring_free(stream->rcvbuf);

      rte_free(stream);
    }
  }

  return 0;
}

static int tcp_process(struct rte_mbuf *tcpmbuf) {
  struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, 
        sizeof(struct rte_ether_hdr));
  struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);	
  // 对比校验和
  uint16_t tcpcksum = tcphdr->cksum;
  tcphdr->cksum = 0; // 先置0初始化
  // tcp check sum调用rte_ipv4_udptcp_cksum后无需大端转小端,其内部做了处理
  uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
  if (cksum != tcpcksum) {
    printf("cksum: %x, tcp cksum: %x\n", cksum, tcpcksum);
    return -1;
  }
  // 通过源地址,目的地址,源端口,目的端口找到对应的stream(即对应的tcp连接)
  struct ht_tcp_stream *stream = ht_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr, 
      tcphdr->src_port, tcphdr->dst_port);
  if (stream == NULL) return -2;
  
  // 存在该stream,判断当前stream的tcp状态进行对应的处理
  switch (stream->status) {

    case HT_TCP_STATUS_CLOSED: //client 
      break;
      
    case HT_TCP_STATUS_LISTEN: // server
      ht_tcp_handle_listen(stream, tcphdr, iphdr);
      break;

    case HT_TCP_STATUS_SYN_RCVD: // server
      ht_tcp_handle_syn_rcvd(stream, tcphdr);
      break;

    case HT_TCP_STATUS_SYN_SENT: // client
      break;

    case HT_TCP_STATUS_ESTABLISHED: { // server | client
      // tcp包的长度等于包的长度减去ipv4头
      int tcplen = rte_ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
      
      ht_tcp_handle_established(stream, tcphdr, tcplen);
      break;
    }

    case HT_TCP_STATUS_FIN_WAIT_1: //  ~client
      break;
      
    case HT_TCP_STATUS_FIN_WAIT_2: // ~client
      break;
      
    case HT_TCP_STATUS_CLOSING: // ~client
      break;
      
    case HT_TCP_STATUS_TIME_WAIT: // ~client
      break;

    case HT_TCP_STATUS_CLOSE_WAIT: // ~server
      ht_tcp_handle_close_wait(stream, tcphdr);
      break;
      
    case HT_TCP_STATUS_LAST_ACK:  // ~server
      ht_tcp_handle_last_ack(stream, tcphdr);
      break;
  }

  return 0;
}


static int ht_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
  uint8_t *srcmac, uint8_t *dstmac, struct ht_tcp_fragment *fragment) {

  // encode 
  const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
              sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
              fragment->optlen * sizeof(uint32_t);

  // 1 ethhdr
  struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
  rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
  rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
  eth->ether_type = rte_htons(RTE_ETHER_TYPE_IPV4);

  // 2 iphdr 
  struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
  ip->version_ihl = 0x45;
  ip->type_of_service = 0;
  ip->total_length = rte_htons(total_len - sizeof(struct rte_ether_hdr));
  ip->packet_id = 0;
  ip->fragment_offset = 0;
  ip->time_to_live = 64; // ttl = 64
  ip->next_proto_id = IPPROTO_TCP;
  ip->src_addr = sip;
  ip->dst_addr = dip;

  ip->hdr_checksum = 0;
  ip->hdr_checksum = rte_ipv4_cksum(ip);

  // 3 tcphdr 
  struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
  tcp->src_port = fragment->sport;
  tcp->dst_port = fragment->dport;
  tcp->sent_seq = rte_htonl(fragment->seqnum);
  tcp->recv_ack = rte_htonl(fragment->acknum);

  tcp->data_off = fragment->hdrlen_off;
  tcp->rx_win = fragment->windows;
  tcp->tcp_urp = fragment->tcp_urp;
  tcp->tcp_flags = fragment->tcp_flags;
  // 如果payload不为NULL则需要拷贝
  if (fragment->data != NULL) {
    uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
    rte_memcpy(payload, fragment->data, fragment->length);
  }

  tcp->cksum = 0;
  tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

  return 0;
}

struct rte_mbuf * ht_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ht_tcp_fragment *fragment) {
  // mempool --> mbuf
  const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
              sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
              fragment->optlen * sizeof(uint32_t); // tcp头里还包含了option的值

  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
  if (!mbuf) {
    rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
  }
  mbuf->pkt_len = total_len;
  mbuf->data_len = total_len;

  uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

  ht_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

  return mbuf;
}

// tcp发送流程
int tcp_out(struct rte_mempool *mbuf_pool) {
  // 获取tcp table
  struct ht_tcp_table *table = g_tcp_tb;
  // 遍历所有的连接是否有数据发送
  struct ht_tcp_stream *stream;
  for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
    if (stream->sndbuf == NULL) continue;
    
    struct ht_tcp_fragment *fragment = NULL;
    int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment); // send buffer中取出一个packet
    if (nb_snd < 0) continue;
    // 如果目的ip存在与arp table中
    uint8_t *dstmac = ht_get_dst_macaddr(stream->sip); // dmac是客户端的源ip
    if (dstmac == NULL) {
      // 目的mac为空,发送arp request
      struct rte_mbuf *arpbuf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, g_default_arp_mac, 
        stream->dip, stream->sip);
      // 发送arp包不直接发送,直接放入到send_ring中即可
      struct ring_buffer *ring = g_ring;
      rte_ring_mp_enqueue_burst(g_ring->send_ring, (void **)&arpbuf, 1, NULL);
      // 把该tcp fragment放入到对应stream的send buffer里
      rte_ring_mp_enqueue(stream->sndbuf, fragment);
    }
    else {
      // arp table中存在该目的mac,1. 构建tcp数据包
      struct rte_mbuf *tcpbuf = ht_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);
      // 2.tcpbuf放入到send_ring中
      struct ring_buffer *ring = g_ring;
      rte_ring_mp_enqueue_burst(ring->send_ring, (void **)&tcpbuf, 1, NULL);
      
      if (fragment->data != NULL)
        rte_free(fragment->data);
      // 一个包入队后需要释放
      rte_free(fragment);
    }

  }

  return 0;
}

#define TCP_BUFFER_SIZE	1024
// hook
static int tcp_server_entry(__attribute__((unused))  void *arg)  {
  int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
  if (listenfd == -1) {
    return -1;
  }

  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(struct sockaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = rte_htonl(INADDR_ANY);
  servaddr.sin_port = rte_htons(9999);
  nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

  nlisten(listenfd, 10);

  while (1) {
    struct sockaddr_in client;
    socklen_t len = sizeof(client);
    int connfd = naccept(listenfd, (struct sockaddr*)&client, &len);

    char buff[TCP_BUFFER_SIZE] = {0};
    while (1) {
      int n = nrecv(connfd, buff, TCP_BUFFER_SIZE, 0); //block
      if (n > 0) {
        printf("recv: %s\n", buff);
        nsend(connfd, buff, n, 0);
      } else if (n == 0) {
        nclose(connfd);
        break;
      } else { //nonblock

      }
    }
  }
  nclose(listenfd);
}
/* end of tcp socket*/

int ht_pkt_process(void *arg) {

  struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
  struct rte_ring *recv_ring = g_ring->recv_ring;
  struct rte_ring *send_ring = g_ring->send_ring;
  
  while (1) {
    struct rte_mbuf *mbufs[BURST_SIZE];
    // 线程安全的消费者消费(出队)
    // 和之前比只是把获取mbufs(数据包)的操作从rte_eth_rx_burst改为从recv_ring从获取。
    // 当然与之对应的，rte_eth_rx_burst中的数据包要在收到后送入recv_ring中
    unsigned num_recvd = rte_ring_mc_dequeue_burst(recv_ring, (void**)mbufs, BURST_SIZE, NULL);
    unsigned i = 0;
    for (i = 0;i < num_recvd; i++) {
      // 从mbufs[i]内存中取出数据包,先解析Ethernet头
      struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
      
      // 对端发送的是arp协议,对arp进行解析
      if (ehdr->ether_type == rte_htons(RTE_ETHER_TYPE_ARP)) {
        // 获取arp头
        struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbufs[i], 
            struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));
        
        char ip_buf[16] = {0};
        // printf("arp ---> src: %s ", inet_ntoa2(arp_hdr->arp_data.arp_tip, ip_buf));
        // printf(" local: %s \n", inet_ntoa2(g_local_ip, ip_buf));
        // 由于arp request是广播,判断目标地址相同才返回arp response
        if (arp_hdr->arp_data.arp_tip == g_local_ip) {
          if (arp_hdr->arp_opcode == rte_htons(RTE_ARP_OP_REQUEST)) {
            // printf("arp --> request\n");
            // 接收到arp request包后返回arp response。注:request里的源ip是response里的目的ip
            struct rte_mbuf *arp_buf = ht_send_arp(mbuf_pool, RTE_ARP_OP_REPLY, arp_hdr->arp_data.arp_sha.addr_bytes, 
              arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip);
            //rte_eth_tx_burst(g_dpdk_port_id, 0, &arpbuf, 1);
            //rte_pktmbuf_free(arp_buf);
            // 带有rte_eth_tx_burst改成全改成入队即可.放入到send ring中处理
            rte_ring_mp_enqueue_burst(send_ring, (void**)&arp_buf, 1, NULL);
            // 处理arp响应的流程(这里对端发送arp reply,这个值要记录到arp表里)
          }
          else if (arp_hdr->arp_opcode == rte_htons(RTE_ARP_OP_REPLY)) {
            // printf("arp --> reply\n");
            
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

              // print_ethaddr("arp table --> mac: ", (struct rte_ether_addr *)addr->hw_addr);

              // printf(" ip : %s \n", inet_ntoa2(addr->ip, ip_buf));
            }

          }
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
        udp_process(mbufs[i]);
      }

      if (iphdr->next_proto_id == IPPROTO_TCP) {
        printf("ht_tcp_process\n");
        tcp_process(mbufs[i]);
      }

      // icmp包的处理
      if (iphdr->next_proto_id == IPPROTO_ICMP) {
        struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);
        char ip_buf[16] = {0};
        printf("icmp ---> src: %s ", inet_ntoa2(iphdr->src_addr, ip_buf));
        // 接收到的是icmp request,回一个icmp reply
        if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

          printf(" local: %s , type : %d\n", inet_ntoa2(iphdr->dst_addr, ip_buf), icmphdr->icmp_type);
          
          struct rte_mbuf *txbuf = ht_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes,
            iphdr->dst_addr, iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

          // rte_eth_tx_burst(g_dpdk_port_id, 0, &txbuf, 1);
          // rte_pktmbuf_free(txbuf);
          rte_ring_mp_enqueue_burst(send_ring, (void**)&txbuf, 1, NULL);

          rte_pktmbuf_free(mbufs[i]);
        }
      }
    }
    udp_out(mbuf_pool);

    tcp_out(mbuf_pool);
  }
  return 0;
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
  // 获取网卡mac地址,用于encode_udp_pkt函数中组建ether头
  rte_eth_macaddr_get(g_dpdk_port_id, (struct rte_ether_addr *)g_src_mac);

  /* 定时器初始化 */
  rte_timer_subsystem_init();
  // 初始化定时器结构arp_timer
  struct rte_timer arp_timer;
  rte_timer_init(&arp_timer);
  // 获取定时器频率,设置定时器
  uint64_t hz = rte_get_timer_hz();
  unsigned lcore_id = rte_lcore_id();
  // PERIODICAL代表多次触发,SINGLE则定时器单次触发
  rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_callback, mbuf_pool);
  /*end of timer init */

  // 创建ring buffer并初始化
  init_global_ring();
  // q全局队列初始化失败,进行差错处理
  if (g_ring == NULL) {
    rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
  }

  if (g_ring->recv_ring == NULL) {
    // 内存中创建一个ring,第一个参数ring的名字,第二个参数ring的大小,第三个参数网口id,第四个参数是flag表明是单生产者或多生产者
    g_ring->recv_ring = rte_ring_create("recv ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
  }
  if (g_ring->send_ring == NULL) {
    g_ring->send_ring = rte_ring_create("send ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
  }

  // 初始化tcp表
  init_tcp_table();

  // 启动另外一个线程用来进行包处理
  /*
  * 第一个参数:线程要执行的函数
  * 第二个参数:传给线程的参数
  * 第三个参数:设置cpu亲和性即该线程要绑定的核心
  */
  // 该函数即为开启另一个线程执行pkt_process函数并且把内存池mbuf传入进去
  // 目前只开一个线程用来处理数据包(收包操作)
  lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
  rte_eal_remote_launch(ht_pkt_process, mbuf_pool, lcore_id);

  // 启动一个dpdk实现的socket api的udp服务器
  lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
  rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);

  // 启动一个tcp server
  lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
  rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);

  while (1) {
    // 改名字为rx_mbufs,因为该mbuf仅收包并做协议解析用
    struct rte_mbuf *rx_mbufs[BURST_SIZE];
    // 第一个参数为端口id(对应网络适配器),第二个参数是指定对应队列,第三个参数是rx_mbufs从内存池里分配的数据
    // 接收数据包,最大数据包数量在init_port中rte_eth_rx_queue_setup设置,设置为128
    unsigned num_recvd = rte_eth_rx_burst(g_dpdk_port_id, 0, rx_mbufs, BURST_SIZE);
    if (num_recvd > BURST_SIZE) {
      rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
    } else if (num_recvd > 0) {
      // 接受到的包大于0,入队recv_ring中进行处理
      rte_ring_sp_enqueue_burst(g_ring->recv_ring, (void**)rx_mbufs, num_recvd, NULL);
    }

    // tx_mbufs,发送数据包所需mbuf
    struct rte_mbuf *tx_mbufs[BURST_SIZE];
    // 从send_ring中取出然后发送数据包
    unsigned num_send = rte_ring_sc_dequeue_burst(g_ring->send_ring, (void**)tx_mbufs, BURST_SIZE, NULL);
    if (num_send > 0) {
      // tx_mbufs是要发送的包,发送完成后需要释放mbuf
      rte_eth_tx_burst(g_dpdk_port_id, 0, tx_mbufs, num_send);

      unsigned i = 0;
      for (i = 0; i < num_send; i++)
        rte_pktmbuf_free(tx_mbufs[i]);

    }

    // 启动定时器,定时执行arp_request_timer_callback函数回调
    uint64_t prev_tsc = 0, cur_tsc; // 上一次时间, 当前时间
    uint64_t diff_tsc;

    cur_tsc = rte_rdtsc();
    diff_tsc = cur_tsc - prev_tsc;
    if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
      rte_timer_manage();
      prev_tsc = cur_tsc;
    }

  }
}
