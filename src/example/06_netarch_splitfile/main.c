#include "common.h"

#include "utils.h"
#include "arp.h"


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

/* end of udp */

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
    printf("arp ---> src: %s ----- %d\n", inet_ntoa2(dst_ip, ip_buf), i);

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

// 收包main函数
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
            rte_ring_mp_enqueue_burst(send_ring, (void**)&arp_buf, 1, NULL);
            // 处理arp响应的流程(这里对端发送arp reply,这个值要记录到arp表里)
          } else if (arp_hdr->arp_opcode == rte_htons(RTE_ARP_OP_REPLY)) {
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
        // rte_eth_tx_burst(g_dpdk_port_id, 0, &txbuf, 1);// rte_eth_rx_burst发送数据
        // rte_pktmbuf_free(txbuf); // 发送用的mbuf同样放回到内存池中
        // 发送udp echo通过送入队列中，在main中从队列取出再发送
        rte_ring_mp_enqueue_burst(send_ring, (void**)&txbuf, 1, NULL);

        rte_pktmbuf_free(mbufs[i]); // 放回内存池
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

          rte_ring_mp_enqueue_burst(send_ring, (void**)&txbuf, 1, NULL);

          rte_pktmbuf_free(mbufs[i]);
        }
      }
    }
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
  g_ring = init_global_ring();
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

  // 启动另外一个线程用来进行包处理
  /*
  * 第一个参数:线程要执行的函数
  * 第二个参数:传给线程的参数
  * 第三个参数:设置cpu亲和性即该线程要绑定的核心
  */
  // 该函数即为开启另一个线程执行pkt_process函数并且把内存池mbuf传入进去
  // 目前只开一个线程用来处理数据包(收包操作)
  rte_eal_remote_launch(ht_pkt_process, mbuf_pool, rte_get_next_lcore(lcore_id, 1, 0));

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
