/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#define RX_RING_SIZE 1024 // 接收环大小
#define TX_RING_SIZE 1024 // 发送环大小

#define NUM_MBUFS 8191	  // mbuf中的元素个数,推荐数量是2的幂次-1.这里猜测是为了避免false shared
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32	  // Burst收发包模式的一次完成多个数据包的收发

static const struct rte_eth_conf port_conf_default = { // 配置端口时使用的默认配置
	.rxmode = {
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
	},
};

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool) // 端口初始化
{
	struct rte_eth_conf port_conf = port_conf_default; // 这个rte_eth_conf结构体在配置网卡时要用到
	const uint16_t rx_rings = 1, tx_rings = 1; // 每个端口有多少个rx和tx这里都为1
	uint16_t nb_rxd = RX_RING_SIZE; // 接受环大小
	uint16_t nb_txd = TX_RING_SIZE; // 发送环大小
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info; // 用于获取以太网设备的信息,设置queue时会用到
	struct rte_eth_txconf txconf;    // 设置tx队列时用到

	if (!rte_eth_dev_is_valid_port(port)) // 检查设备的port_id是否已连接
		return -1;
	// 查询以太网设备的信息,参数port指示以太网设备的网口标识符,第二个参数指向要填充信息的类型rte_eth_dev_info的结构的指针
	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	// rte_eth_dev_configure() 配置网卡
	/* 四个参数
		1. port id
		2. 要给该网卡配置多少个收包队列 这里是一个
		3. 要给该网卡配置多少个发包队列 也是一个
		4. 结构体指针类型 rte_eth_conf * 
	*/
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;
	// rte_eth_dev_adjust_nb_rx_tx_desc() 检查Rx和Tx描述符的数量是否满足以太网设备信息中的描述符限制,否则将它们调整为边界。
	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;
	/* rte_eth_rx_queue_setup() 配置rx队列(rx是接收)
		配置rx队列需要6个参数
		1. port id
		2. 接收队列的索引.要在[0, rx_queue - 1]范围内,是在rte_eth_dev_configure中配置的
		3. 为接收队列分配的接收描述符(接收队列大小)
		4. socket id.如果是numa架构就使用rte_eth_dev_socket_id(port)获取port所对应的以太网设备所连接上的socket的id;
			若不是NUMA,该值可以是宏SOCKET_ID_ANY
		5. 如果rx queue的配置数据的指针.如果是NULL则使用默认配置
		6. 指向内存池mempool的指针,从中分配mbuf去操作队列
	*/
	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}
	// rte_eth_txconf的配置赋值,注意rte_eth_rx_queue_setup函数第五个参数需要传入的结构体是rte_eth_rxconf,只是设置rx对立时采用默认
	// rte_eth_txconf结构很明显作为rte_eth_tx_queue_setup的第五个参数控制tx队列的行为
	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	/* rte_eth_tx_queue_setup()
	配置tx队列需要五个参数（不需要mempool）
		1. port id
		2. 发送队列的索引。要在[0, tx_queue - 1] 的范围内(先前rte_eth_dev_configure中配置的)
		3. 为发送环分配的接收描述符数(自定义环的大小)
		4. socket id
		5. 指向tx queue的配置数据的指针,结构体是rte_eth_txconf。
	*/
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	// 启动设备
	// 设备启动步骤是最后一步,包括设置已配置的offload功能以及启动设备的发送和接收单元.
	// 成功时,可以调用以太网API导出的所有基本功能(链接状态，接收/发送等)
	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
	// 获取端口的mac地址
	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	// 十六进制数形式输出整数一个h表示short,即short int,两个h表示short short即 char.%hhx用于输出char
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port); // 开启网卡混杂模式

	return 0;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
lcore_main(void)
{
	uint16_t port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	 // 当有NUMA结构时,检查网口是否在同一个NUMA node节点上,只有在一个NUMA node上时线程轮询的效率最好
	RTE_ETH_FOREACH_DEV(port) // 若以太网口所在的NUMA socket号与当前线程所在的 socket 号不同,报warming
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
			rte_lcore_id());
	
	/*
		一个端口收到包，就立刻转发到另一个端口
		0 和 1 
		2 和 3
		……
	*/
	/* Run until the application is quit or killed. */
	for (;;) {
		/*
		 * Receive packets on a port and forward them on the paired
		 * port. The mapping is 0 -> 1, 1 -> 0, 2 -> 3, 3 -> 2, etc.
		 */
		RTE_ETH_FOREACH_DEV(port) {

			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE]; // mbuf的结构体收到的包存在这里,也是要发出去的包
			/* 收包函数: rte_eth_rx_burst 从以太网设备的接收队列中检索一连串(burst收发包机制)接收数据包.检索到的数据包存储在rte_mbuf结构中。
			参数四个
				1. port id(收到哪个网口)
				2. 队列索引(确定是哪一条队列)，范围要在[0, rx_queue - 1] 的范围内(rte_eth_dev_configure中设置的,这个程序设置的是1所以只能填0)
				3. 指向rte_mbuf结构的指针数组的地址.要够容纳第四个参数所表示的数目的指针.(把收到的包存在哪里?存在这里的)
				4. 要检索的最大数据包数
			
			rte_eth_rx_burst()是一个循环函数，从RX队列中收包达到设定的最大数量为止。

			收包操作：
			1. 根据NIC的RX描述符信息，初始化rte_mbuf数据结构。
			2. 将rte_mbuf（也就是数据包）存储到第三个参数所指示的数组的下一个条目。
			3. 从mempool分配新的的rte_mbuf
			*/

			const uint16_t nb_rx = rte_eth_rx_burst(port, 0,
					bufs, BURST_SIZE);

			if (unlikely(nb_rx == 0)) // 返回值是实际收到的数据包数
				continue;
			/* 发包函数: rte_eth_tx_burst从为port id的以太网设备中放数据包到传输队列(由索引指示)然后发送一连串输出数据包。
			参数四个：
				1. port id(从哪个网口)
				2. 队列索引(确定是哪条队列发出),范围要在[0, tx_queue - 1] 的范围内(rte_eth_dev_configure中的设置的)
				3. 指向包含要发送的数据包的rte_mbuf结构的指针数组的地址.(要发送的包的内容在哪里)
				4. 要发送的数据包的最大数量.

			返回值是发送的包的数量。

			发包操作：
			1. 选择发包队列中下一个可用的描述符
			2. 使用该描述符发送包,之后释放对应的mempool空间
			3. 再根据 *rte_mbuf 初始化发送描述符
			*/

			/* Send burst of TX packets, to second port of pair. */
			const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
					bufs, nb_rx); // port 异或 1 --> 0就和1是一对,2就和3是一对.0收到包就从1转发,3收到包就从2口转发.

			/* Free any unsent packets. */
			if (unlikely(nb_tx < nb_rx)) {
				uint16_t buf;
				for (buf = nb_tx; buf < nb_rx; buf++)
					rte_pktmbuf_free(bufs[buf]);
			}
		}
	}
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool; // 指向内存池结构的指针
	unsigned nb_ports; // 端口个数
	uint16_t portid;   // 端口号

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail(); // 获取当前可用以太网设备的总数
	if (nb_ports < 2 || (nb_ports & 1))   // 检查端口个数是否小于两个或是奇数,则出错
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");
	// dpdk用mbuf保存数据包,mempool用于操作mbuf
	/* rte_pktmbuf_pool_create() 创建并初始化mbuf池，是 rte_mempool_create 这个函数的封装。
		五个参数：
		1. mbuf的名字 "MBUF_POOL"
		2. mbuf中的元素个数。每个端口给了8191个
		3. 每个核心的缓存大小，如果该参数为0 则可以禁用缓存。本程序中是250
		4. 每个mbuf中的数据缓冲区大小
		5. 应分配内存的套接字标识符。
		返回值：分配成功时返回指向新分配的mempool的指针。

		mempool的指针会传给 port_init 函数，用于 setup rx queue
	*/
	/* Creates a new mempool in memory to hold the mbufs. */
	// rte_socket_id()返回正在运行的lcore所对应的物理socket。socket的文档在 lcore中
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n"); // 若mempool分配失败

	/* Initialize all ports. 在每个端口上执行初始化 */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);

	if (rte_lcore_count() > 1) // basicfwd只需要使用一个逻辑核
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	// 仅仅一个主线程调用
	// 这个程序纯粹地把一个网口收到的包从另一个网口转发出去，就像是一个repeater，中间没有其他任何处理。
	lcore_main(); // 如果多个线程调用主线程会使用到dpdk的另一个api rte_eal_remote_launch

	return 0;
}
