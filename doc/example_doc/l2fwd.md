# l2fwd源码分析

l2fwd是dpdk二层转发示例，它会将一个口收到的报文经过相邻口转发出去，在日常测试中经常用到。当拿到一张网卡验证其厂商提供的驱动是否有效时往往该用例是用来测试的最好办法。

下面进行该代码的源码分析，最后会给出如何使用l2fwd。

## 1.源码分析

带有详细注释的源码可以在 [example-code/l2fwd](../../example-code/l2fwd/) 文件夹找到。

### 1.1 l2fwd初始化 eal 并解析参数

1. 调用`ret = rte_eal_init(argc, argv);`初始化eal环境

```c
	argc -= ret; // l2fwd需要调整argc与argv的位置以
	argv += ret; // 解析l2fwd自定义的参数
``` 

2. 调整 argc 与 argv 的位置以解析 l2fwd 自定义的参数。

3. 将 force_quit 变量设置为 false，行注册了 SIGINT 与 SIGTERM 的信号处理函数 signal_handler。当用户触发SIGINT 与 SIGTERM 信号时修改force_quit标志位。用来启停l2fwd。

停止的代码如下:

```c
	// force_quit为true后主动退出,释放占用接口
	RTE_ETH_FOREACH_DEV(portid) { // RTE_ETH_FOREACH_DEV循环判断当前接口是否是l2fwd使能的接口
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");
```

可以看到dpdk网口停止的api为`rte_eth_dev_stop`而关闭该网口的api为`rte_eth_dev_close`。

### 1.2 l2fwd_parse_args 函数

l2fwd 支持三个参数，-p 参数使用十六进制掩码表示要使能的接口，每一位表示一个接口；-q 参数用于指定每个核上的队列数目；-T 参数用于指定时间周期，不太常用。

其源码如下:

```c
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p': // 获取使能接口存入变量l2fwd_enabled_port_mask
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* nqueue */
		case 'q': // 每个核上收包队列
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T': // 过期时间
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}
```

l2fwd_parse_args调用如下所示:

```
l2fwd_parse_portmask

l2fwd_usage

l2fwd_parse_nqueue

l2fwd_parse_timer_period
```

l2fwd 通过 `getopt_long` 依次解析每个参数，`optarg` 指向参数的值，通过调用 `strtoul`、`strtol` 来解析参数值并存储到相应的变量中。

参数解析完成后，`l2fwd_enabled_port_mask` 变量保存 l2fwd `程序要使能的接口，l2fwd_rx_queue_per_lcore` 变量保存每一个逻辑核上的 rx 队列数目，timer_period 保存 drain 的时间。

### 1.3 创建 pktmbuf pool 并 初始化 l2fwd_dst_ports 结构体

下面是相应代码如下:

```c
	/* reset l2fwd_dst_ports */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0; // 初始化l2fwd_dst_ports
	last_port = 0;

    // 省略

    // 省略

	/* create the mbuf pool */ // 创建pktmbuf pool
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL) // 创建失败后,打印失败消息并退出
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
```

上面的代码首先：reset 了 `l2fwd_dst_ports`，此数组用于保存相邻转发接口的关系，在收发包线程中被访问用于确定发包使用的端口号(出接口或者网口)。

然后通过`rte_pktmbuf_pool_create`创建了 l2fwd 的 pktmbuf 内存池，pktmbuf 统一在 pktmbuf 内存池中分配回收，当创建失败后 l2fwd 打印失败信息并退出。

`RTE_ETH_FOREACH_DEV`遍历可用接口数量,如果为0（即`nb_ports_available`为0）则失败退出。

### 1.4 初始化转发端口关系数组

完整代码如下，这段代码是转发的重中之重。

```c
	/* 每个逻辑内核在每个端口上都分配有一个专用的 TX 队列
	 * Each logical core is assigned a dedicated TX queue on each port.
	 */
	RTE_ETH_FOREACH_DEV(portid) { // 遍历端口,初始化转发端口关系数组
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) // 忽略没有使能的端口
			continue;
        // l2fwd_dst_ports保存了相邻转发接口的关系,该变量在收发包线程中被使用,用于确定发包使用的端口号
		if (nb_ports_in_mask % 2) { // 上一个口使用下一个口发包,下一个口使用上一个口发包
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;
	}
	if (nb_ports_in_mask % 2) { // 最后的单个口发包使用当前端口
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}
```

上面代码生成了`l2fwd_dst_ports`端口的关联表，**确定每个使能端口的发包端口。**当使能的端口数目为偶数时，**上一个口使用下一个口发包，下一个口使用上一个口发包**，当使能的端口数目为奇数时，**最后的单个口发包使用当前口**。

### 1.5 初始化每个lcore上绑定的收包端口关系数组

l2fwd 支持在单个 lcore 上绑定多个口进行收包，为此 l2fwd 定义了 `lcore_queue_conf` 结构体，此结构体的数量为系统支持的 lcore 的最大值。

```c
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16
struct lcore_queue_conf { // 逻辑核上的配置
	unsigned n_rx_port;	// 该lcore上绑定多少个端口,也作为下一个数组的下标(0-n-1)
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];// 存放一系列端口号,标记绑定的端口
} __rte_cache_aligned; // poll module driver 思想。绑定 lcore 和 port，特定的 lcore 轮询对应的一个或多个 port
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE]; // 通过RTE_MAX_LCORE来建立数组,这样就可以使用lcore_id来隔离每个lcore和queue_conf配置
```

`n_rx_port` 代表一个 `lcore_queue_conf` 中绑定的收包端口数目，`rx_port_list` 中保存 `lcore_queue_conf` 中的每一个收包端口的 `portid`。

`RTE_MAX_LCORE` 的作用在于通过使用 lcore_id 这种每线程数据来隔离每个 lcore 的 queue_conf 配置。

lcore_queue_conf 初始化代码如下：

```c
	rx_lcore_id = 0;
	qconf = NULL;

	/* Initialize the port/queue configuration of each logical core */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		// // n_rx_port代表lcore_queue_conf 中绑定的收包端口数目
		/* get the lcore_id for this port */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}

		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}
		// rx_port_list 中保存 lcore_queue_conf 中的每一个收包端口的 portid
		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
		printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
	}
```

上述的宏`RTE_ETH_FOREACH_DEV`相当于`for (portid = 0; portid < nb_ports; portid++)`作用是遍历所有网口。

```c
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
		       lcore_queue_conf[rx_lcore_id].n_rx_port ==
		       l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}
```

while循环中的代码大致逻辑是为当前 port 找到一个可用的 lcore_id，当 lcore_id 被使能，且此 lcore_id 对应的 `queue_conf` 中绑定的收包接口数目不等于 `l2fwd_rx_queue_per_lcore`（解析参数设定的每个核上的队列数目）时，此 lcore_id 可用。

不满足如上要求时，lcore_id 递增，当 lcore_id 的数目超过系统支持的最大 lcore 数目时，程序打印异常信息并退出。


```c
		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			/* Assigned a new logical core in the loop above. */
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}
```

这个if语句是获取当前接口使用的 lcore 对应的 lcore_queue_conf 结构体地址。

```c
		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;
```

最后的代码将当前的 portid 赋值给 lcore_queue_conf 结构体中 rx_port_list 数组中的对应项目，然后对 n_rx_port 加 1，表示此 lcore_queue_conf 中绑定的端口数目又增加了一个。

l2fwd 默认在一个 lcore 上绑定一个接口，这样使能了几个接口就需要相应数目的 lcore，当 lcore 不足时就会因为无法分配 lcore 而退出。

### 1.6 初始化所有接口(网口)

```c
	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(portid) { // 左边宏定义相当于 for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		/* skip ports that are not enabled */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}
		nb_ports_available++;

		/* init port */ // 初始化所有端口
		printf("Initializing port %u... ", portid);
		fflush(stdout);
		rte_eth_dev_info_get(portid, &dev_info); // 获取dev信息,判断是否支持设备支持优化 mbufs 的快速释放
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);// 配置使用一个收发队列,设置local_port_conf
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);
		// 获取当前接口的mac地址并填充到l2fwd_ports_eth_addr数组中当前接口占用的表项中
		rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);
		// 这一mac地址在l2fwd_simple_forward函数修改报文的源mac地址时被使用,是典型的使用空间换时间的案例
		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     l2fwd_pktmbuf_pool); // 初始化rx队列,设置每个queue上的描述符以及使用的pktmbuf
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);
		// 初始化tx队列,设置每个queue上的描述符以及使用的pktmbuf
		/* init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);
		// 初始化当前port的rte_eth_dev_tx_buffer结构
		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);
		// 注册的回调是rte_eth_tx_buffer_count_callback其调用rte_pktmbuf_free将没有成功发送出去的包释放掉,缺少这一过程会导致mbuf泄露
		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("done: \n");

		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}
```

`RTE_ETH_FOREACH_DEV`宏遍历所有网口。

而其中`nb_ports_available`变量的值代表dpdk可用的接口数目，检测到一个dpdk可用的接口会将`nb_ports_available`变量加一，当`RTE_ETH_FOREACH_DEV`宏循环结束的时候，判断`nb_ports_available`是否为0，为0则表示没有使能一个接口，打印错误信息并退出，代码如下。

```c
	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE,
			"All available ports are disabled. Please set portmask.\n");
	}
```

当至少有一个接口使能时，配置的逻辑会被执行。

```c
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);// 配置使用一个收发队列,设置local_port_conf
```

上面调用 `rte_eth_dev_configure` 配置使用一个收发队列，且设置 port_conf。

```c
rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);
```

获取当前接口的 mac 地址并填充到 `l2fwd_ports_eth_addr` 数组中当前接口占用的表项中，这一 mac 地址在 `l2fwd_simple_forward` 函数修改报文的源 mac 地址时被使用，是典型的使用空间换时间的案例。

```c
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     l2fwd_pktmbuf_pool); // 初始化rx队列,设置每个queue上的描述符以及使用的pktmbuf
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);
		// 初始化tx队列,设置每个queue上的描述符以及使用的pktmbuf
		/* init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
```

上述代码初始化 rx queue 与 tx queue，设置每个 queue 上的描述符数目及使用的 pktmbuf 内存池，当设置失败时打印异常信息后退出。

```c
		// 初始化当前port的rte_eth_dev_tx_buffer结构
		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);
		// 注册的回调是rte_eth_tx_buffer_count_callback其调用rte_pktmbuf_free将没有成功发送出去的包释放掉,缺少这一过程会导致mbuf泄露
		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
```

上面的代码初始化当前 port 的 `rte_eth_dev_tx_buffer` 结构，此结构定义如下：

```c
struct rte_eth_dev_tx_buffer {
    buffer_tx_error_fn error_callback;
    void *error_userdata;
    uint16_t size;           /**< Size of buffer for buffered tx */
    uint16_t length;         /**< Number of packets in the array */
    struct rte_mbuf *pkts[];
    /**< Pending packets to be sent on explicit flush or when full */
};
```

可以看到 pkts 数组没有设定大小，调用 `rte_zmalloc_socket` 的时候，传递的大小为 `RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST)`。

`RTE_ETH_TX_BUFFER_SIZE` 的定义如下：

```c
#define RTE_ETH_TX_BUFFER_SIZE(sz)
(sizeof(struct rte_eth_dev_tx_buffer) + (sz) * sizeof(struct rte_mbuf *))
```

可以发现它额外创建了 `MAX_PKT_BURST` 个指针，pkts 就指向这一额外内存区域，能够直接获取填充的 mbuf 地址。

`rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);`初始化 tx_buffer，注意此函数的第二个参数，这个参数指定了一个阀值，当 tx_buffer 中的包数目低于此阀值时 `rte_eth_tx_buffer` 不会立刻发包出去，类似于缓冲功能。

同时需要说明的是 `rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);` 会注册一个默认的回调函数 `rte_eth_tx_buffer_drop_callback`，此回调函数会调用 `rte_pktmbuf_free` 将没有成功发送出去的包释放掉，缺少这一过程会导致 mbuf 泄露。

`ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],rte_eth_tx_buffer_count_callback,&port_statistics[portid].dropped);`重新注册了一个回调函数，此回调函数在调用 rte_pktmbuf_free 释放未成功发送的报文后会将未成功发送的报文数目加到每个接口的 dropped 字段上。

`rte_eth_dev_start(portid);`start 接口，然后`rte_eth_promiscuous_enable(portid);`开启混淆模式，输出当前接口的 mac 地址并清空 l2fwd 的接口统计数据。
start 接口时会 up 接口，只有当接口处于 up 状态才能正常收发包，在收发包之前需要检查接口链路状态。

`check_all_ports_link_status(nb_ports, l2fwd_enabled_port_mask);`就是检查接口 link 状态的逻辑，`check_all_ports_link_status` 会在 9s 内不断调用 `rte_eth_link_get_nowait` 获取每一个接口的 link 状态，当所有使能接口都 up、timeout 时，函数会设置 `print_flag` 变量为 1，打印接口状态信息后返回。

### 1.7 在每个lcore上运行l2fwd_launch_one_lcore函数

```c
	ret = 0;
	/* launch per-lcore init on every lcore */ // 在每个core上运行l2fwd_launch_one_lcore函数
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
	// force_quit为true后主动退出,释放占用接口
	RTE_ETH_FOREACH_DEV(portid) { // RTE_ETH_FOREACH_DEV循环判断当前接口是否是l2fwd使能的接口
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");
```

`rte_eal_mp_remote_launch` 在每个使能的 `lcore` 上初始化将要运行的函数，设定每个 lcore 对应的 `lcore_config` 数据结构，并立即执行。


```c
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}
```

依次获取每个 slave lcore 线程的状态，当 rte_eal_wait_lcore 函数返回值小于 0 时跳出循环。

### 1.8 收发包线程的执行过程

主要执行的函数如下:

```c
static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}
```

l2fwd_lanuch_one_lcore 会在每一个收发包线程上执行，它通过调用 l2fwd_main_loop 完成工作。

l2fwd的实际运行函数是`l2fwd_main_loop`。

```c
/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;
	// 获取到当前线程的lcore_id
	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id]; // 获取到当前lcore_queue_conf中的表项
	// 判断当前lcore绑定的收包端口数目,为0表示不收包.一般为master线程
	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}
	// 收发包循环
	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/* 发送数据包流程
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {

			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
				buffer = tx_buffer[portid];
				// 立刻发出buffer中的报文
				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent; // 增加tx统计

			}

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on master core */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);
			// 增加rx统计
			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				l2fwd_simple_forward(m, portid); // 收到的报文调用l2fwd_simple_forward
			}
		}
	}
}
```

```c
	// 获取到当前线程的lcore_id
	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id]; // 获取到当前lcore_queue_conf中
```

上述代码获取lcore_id，然后使用id获取到的`lcore_queue_conf`中的表项。

```c
	// 判断当前lcore绑定的收包端口数目,为0表示不收包.一般为master线程
	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}
```

接着判断当前lcore绑定的收包端口数目，为0表示不收包，一般来说这是master线程。



## 使用l2fwd

运行参数解析:

```
-c : 设置要运行的内核的十六进制位掩码,使用-l更加直观.
-l : 要运行的核心列表.
-n : 每个CPU的内存通道数.
--  : 表示之后为次参数
-q : 每个CPU管理的队列数，这里使用默认值.
-p : PORTMASK: 要使用的端口的16进制位图，此处设置为第3个端口.
```


运行效果:

```shell
sudo ./l2fwd -l 0-3 -n 4 -- -p 0x3
EAL: Detected 4 lcore(s)
EAL: Detected 1 NUMA nodes
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
EAL: No available hugepages reported in hugepages-1048576kB
EAL: Probing VFIO support...
EAL: PCI device 0000:02:01.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 8086:100f net_e1000_em
EAL: PCI device 0000:03:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 15ad:7b0 net_vmxnet3
EAL: PCI device 0000:0b:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 15ad:7b0 net_vmxnet3
EAL: PCI device 0000:13:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 15ad:7b0 net_vmxnet3
MAC updating enabled
Lcore 0: RX port 0
Lcore 1: RX port 1
Initializing port 0... done: 
Port 0, MAC address: 00:0C:29:4F:5F:E0

Initializing port 1... done: 
Port 1, MAC address: 00:0C:29:4F:5F:EA

Skipping disabled port 2

Checking link statusdone
Port0 Link Up. Speed 10000 Mbps - full-duplex
Port1 Link Up. Speed 10000 Mbps - full-duplex
L2FWD: entering main loop on lcore 1
L2FWD:  -- lcoreid=1 portid=1
L2FWD: lcore 3 has nothing to do
L2FWD: entering main loop on lcore 0
L2FWD:  -- lcoreid=0 portid=0

Port statistics ====================================
Statistics for port 0 ------------------------------
Packets sent:                  1871351
Packets received:              1525888
Packets dropped:                     0
Statistics for port 1 ------------------------------
Packets sent:                  1525888
Packets received:              1871383
Packets dropped:                     0
Aggregate statistics ===============================
Total packets sent:            3397239
Total packets received:        3397271
Total packets dropped:               0
====================================================
^C

Signal 2 received, preparing to exit...
Closing port 0... Done
Closing port 1... Done
Bye...
```

二层转发和普通的端口转发(basicfwd)区别如下:

| feature   |              l2fwd              |                basicfwd                 |
| :-------- | :-----------------------------: | :-------------------------------------: |
| 端口数量  |  使用端口掩码来指定,支持奇数个  |      单同样通过端口掩码,只能偶数个      |
| lcore数量 |   多个,每个lcore负责一个port    |           一个,执行类似中继器           |
| 转发逻辑  |       转发时会改写mac地址       | 只能说0<->1,2<->3这样成对的port互相转发 |
| tx_buffer | 有发包缓存,收到的包会缓存到发包 |                 单元格                  |


