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
          if (!ht_arp_in(mbufs[i], mbuf_pool)) {
            continue;
          }
      }
      
      if (ehdr->ether_type != rte_htons(RTE_ETHER_TYPE_IPV4)) { // 判断是否是ip协议
        continue; // 不是ip协议不做处理
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
  rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, ht_arp_out_callback, mbuf_pool);
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
