

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096-1)

#define BURST_SIZE	32

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
	rte_eth_dev_info_get(gDpdkPortId, &dev_info);
	// 配置rx队列和tx队列的数量
	const int num_rx_queues = 1; // 最多8个
	const int num_tx_queues = 0;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

	// 设置哪一个队列去接收数据, 128是队列承载的数据包最大数量
	if (rte_eth_rx_queue_setup(gDpdkPortId, 0 , 128, 
		rte_eth_dev_socket_id(gDpdkPortId),NULL, mbuf_pool) < 0) {

		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

	}
	// 启动接收队列
	if (rte_eth_dev_start(gDpdkPortId) < 0 ) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

	

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
			if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) { // 判断是否是ip协议
				continue; // 不是ip协议不做处理
			}
			// 是ip协议取出来
			struct rte_ipv4_hdr *iphdr =  rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
				sizeof(struct rte_ether_hdr));
			// 对udp做处理
			if (iphdr->next_proto_id == IPPROTO_UDP) {
				// udp的头
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

				uint16_t length = ntohs(udphdr->dgram_len); // 两个字节以上都要转换ntohs
				*((char*)udphdr + length) = '\0';	// 最后一段置为0
				// 打印接收到的udp数据
				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src: %s:%d, ", inet_ntoa(addr), udphdr->src_port);

				addr.s_addr = iphdr->dst_addr;
				printf("dst: %s:%d, %s\n", inet_ntoa(addr), udphdr->src_port, 
					(char *)(udphdr+1));

				rte_pktmbuf_free(mbufs[i]); // 放回内存池
			}
			
		}

	}

}




