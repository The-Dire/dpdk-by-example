

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>


#define ENABLE_SEND		1



#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32


#if ENABLE_SEND
// 六元组用来解析sip,dip,smac,dmac,sport,dport用来发送数据包,这里设置全局不好只实验用
static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif


int gDpdkPortId = 0; // 端口id

// 端口默认信息
static const struct rte_eth_conf port_conf_default = {
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};
// 绑定网卡
static void ng_init_port(struct rte_mempool *mbuf_pool) {

	uint16_t nb_sys_ports= rte_eth_dev_count_avail(); // 1. 检测端口是否合法,是否设置
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}
	// 默认网卡信息获取
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(gDpdkPortId, &dev_info); //
	// 配置rx队列和tx队列的数量
	const int num_rx_queues = 1;
	const int num_tx_queues = 1;	// 写队列置为1
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	// 设置哪一个队列去接收数据, 1024是队列承载的数据包最大数量
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 1024, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}
	// 启动tx队列,tx队列的初始化
#if ENABLE_SEND
	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.rxmode.offloads; // 上面的设置:即接收的包多大就发多大的数据包
	if (rte_eth_tx_queue_setup(gDpdkPortId, 0 , 1024, // 参数为: 对应网口,对应的队列,队列最大包数量,socket id,send的配置
		rte_eth_dev_socket_id(gDpdkPortId), &txq_conf) < 0) {
		
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
		
	}
#endif
	// 启动对应的队列,这里是既有接收队列也有发送队列
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

	

}

// 构建一个最小的udp包,data是要发送的udp的payload
static int ng_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len) {

	// encode 构建udp包

	// 1 ethhdr头
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);// 源ip
	rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);// 目的ip
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);	// 设置类型为ipv4
	

	// 2 iphdr 设置ip头
	// msg + sizeof(struct rte_ether_hdr相当于eth+1
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0; // ip的类型
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr)); // 转成网络字节序(大端序)
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_UDP; // ip头要标识下一个是什么协议
	ip->src_addr = gSrcIp;
	ip->dst_addr = gDstIp;
	
	ip->hdr_checksum = 0; // 一开始置0防止checksum计算出错 
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 udphdr 

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	udp->src_port = gSrcPort;
	udp->dst_port = gDstPort;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen); // 数据放到udp头之下,udp+1为以udp hdr为一单元偏移。就是偏移到udp hdr末尾

	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	struct in_addr addr;
	addr.s_addr = gSrcIp;
	printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort)); // 网络字节序大端序转为主机字节序小端序

	addr.s_addr = gDstIp;
	printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

	return 0;
}

// 发送数据包,参数分别为:内存buffer,payload,length数据(payload)长度
static struct rte_mbuf * ng_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length) {

	// mempool --> mbuf(从mempool里获取数据buffer流)

	const unsigned total_len = length + 42; // 42是eth header + ip hdr + udp hdr

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len; // 包的长度
	mbuf->data_len = total_len; // 数据的长度
	// 偏移uint8_t也就是一个字节一个字节处理
	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_pkt(pktdata, data, total_len);

	return mbuf;

}


int main(int argc, char *argv[]) {
	// dpdk环境初始化,巨页,内存,cpu亲和等的设置
	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
		
	}
	// 确定内存池,收发的数据都要放入其中
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
		0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	ng_init_port(mbuf_pool);
	// 获取网卡mac地址,用于ng_encode_udp_pkt函数中组建ether头
	rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac); // 获取到了源mac

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE];
		// 第一个参数为端口id(对应网络适配器),第二个参数是指定对应队列,第三个参数是mbufs从内存池里分配的数据
		// 接收数据包,最大数据包数量在ng_init_port中rte_eth_rx_queue_setup设置,设置为128
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}
		// 操作数据包
		unsigned i = 0;
		for (i = 0;i < num_recvd;i ++) {
			// 从mbufs[i]内存中取出数据包
			struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { // 判断是否是ipv4协议
				continue; // 不是ip协议不做处理
			}
			// 是ip协议取出来
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			// 对udp做处理
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				// udp的头
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

#if ENABLE_SEND // 发送包需要的六元组剩下的dmac,sip,dip,sport,dport获取
				// 收到包后,给六元组赋值。通过六元组把包echo回包发送主机
				rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				
				rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));

#endif

				uint16_t length = ntohs(udphdr->dgram_len); // 两个字节以上都要转换ntohs
				*((char*)udphdr + length) = '\0'; // 最后一字节置为'\0'即结束符
				// 打印接收到的udp数据
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), 
					(char *)(udphdr+1));

#if ENABLE_SEND
				// 获取到构建好数据包的内存池
				struct rte_mbuf *txbuf = ng_send(mbuf_pool, (uint8_t *)(udphdr+1), length);
				rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);// rte_eth_rx_burst发送数据
				rte_pktmbuf_free(txbuf);
				
#endif

				rte_pktmbuf_free(mbufs[i]); // (释放)mbuf放回内存池
			}
			
		}

	}

}




