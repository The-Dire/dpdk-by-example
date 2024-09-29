# DPDK常用api速查表

dpdk只是用的话需要知道的api并不多，本文就主要把常用的api做个总结。

dpdk程序收包流程:

1. `rte_eal_init`:初始化dpdk所需环境
2. `rte_pktmbuf_pool_create`: 创建内存池
3. 初始化dpdk端口
4. 进入包处理循环
5. 创建mbuf。`struct rte_mbuf *mbufs[BURST_SIZE];`
6. 启动收包。`rte_eth_rx_burst(g_dpdk_port_id, 0, mbufs, BURST_SIZE);`
7. 处理收到的包，进行位偏移

dpdk程序发包流程:

前三步相同
4. 发包处理
5. 创建mbuf
6. 启动发包

所以需要总结的基础api有，初始化网口需要的api，收发包api。由于dpdk中队列往往是最常使用的api，还会额外总结dpdk ring api。

## eal环境初始化

rte_eal_init函数，第一个参数是参数数量，第二个参数是参数的实际内容。

```c
	/* init EAL 初始化eal环境*/
	ret = rte_eal_init(argc, argv);
```

## 创建mbuf池

dpdk中的mbuf类似于内核中的skb，是数据包的载体。

```c
    struct rte_mempool *mbuf_pool; // 指向内存池结构的指针
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
```

## 网口配置

更多细节请参考 [basicfwd.c](../../example-code/skeleton/basicfwd.c)中的`port_init`函数相关代码，主要关注`rte_eth_dev_configure`,`rte_eth_rx_queue_setup`,`rte_eth_tx_queue_setup`这三个函数。

最后还需要启动设备，函数为`rte_eth_dev_start`。

```c
/* Configure the Ethernet device. */
// rte_eth_dev_configure() 配置网卡
/* 四个参数
    1. port id
    2. 要给该网卡配置多少个收包队列 这里是一个
    3. 要给该网卡配置多少个发包队列 也是一个
    4. 结构体指针类型 rte_eth_conf * 
*/
retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);

/* rte_eth_rx_queue_setup() 配置rx队列(rx是接收)
    配置rx队列需要6个参数
    5. port id
    6. 接收队列的索引.要在[0, rx_queue - 1]范围内,是在rte_eth_dev_configure中配置的
    7. 为接收队列分配的接收描述符(接收队列大小)
    8. socket id.如果是numa架构就使用rte_eth_dev_socket_id(port)获取port所对应的以太网设备所连接上的socket的id;
        若不是NUMA,该值可以是宏SOCKET_ID_ANY
    9. 如果rx queue的配置数据的指针.如果是NULL则使用默认配置
    10. 指向内存池mempool的指针,从中分配mbuf去操作队列
*/
retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
        rte_eth_dev_socket_id(port), NULL, mbuf_pool);

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

retval = rte_eth_tx_queue_setup(port, q, nb_txd,
        rte_eth_dev_socket_id(port), &txconf);


// 启动设备
// 设备启动步骤是最后一步,包括设置已配置的offload功能以及启动设备的发送和接收单元.
// 成功时,可以调用以太网API导出的所有基本功能(链接状态，接收/发送等)
/* Start the Ethernet port. */
retval = rte_eth_dev_start(port);
```

## 收发包

```c
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
```

## 队列操作

1. 队列创建

```c
    // 内存中创建一个ring,第一个参数ring的名字,第二个参数ring的大小,第三个参数网口id,第四个参数是flag表明是单生产者或多生产者
    rte_ring *recv_ring = rte_ring_create("recv ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
```

2. 入队

```c
struct rte_mbuf *bufs[DPDKCAP_CAPTURE_BURST_SIZE];
// 接收到的数据包送入recv_ring队列里
/* Retrieve packets and put them into the ring */
nb_rx = rte_eth_rx_burst(config->port, config->queue,
    bufs, DPDKCAP_CAPTURE_BURST_SIZE);
/**
 * 将多个对象入队。
 *
 * 此函数根据环创建时指定的默认行为调用多生产者或单生产者版本（请参阅rte_ring_create传入的flag参数，第四个参数）。
 *
 * @param r
 *   指向环结构的指针。
 * @param obj_table
 *   指向 void * 指针，即待入队对象数组的指针。
 * @param n
 *   从 obj_table 中添加到环中的对象数量。
 * @param free_space
 *   如果非 NULL，则返回入队操作完成后环中的空闲数量。
 * @return
 *   - n: 入队对象的实际数量。
 */
nb_rx_enqueued = rte_ring_enqueue_burst(recv_ring, (void*) bufs,
    nb_rx, NULL);

// 与此同时还有显式指定是否多生产者安全的api，入参和返回值和rte_ring_enqueue_burst一致

// 入队函数，非多生产者安全
static __rte_always_inline unsigned
rte_ring_sp_enqueue_burst(struct rte_ring *r, void * const *obj_table,
			 unsigned int n, unsigned int *free_space);
// 入队函数，多生产者安全(线程安全)
static __rte_always_inline unsigned
rte_ring_mp_enqueue_burst(struct rte_ring *r, void * const *obj_table,
			 unsigned int n, unsigned int *free_space);
```

3. 出队


```c
struct rte_mbuf * dequeued[DPDKCAP_WRITE_BURST_SIZE];
/**
 * 将多个对象从环中出列，最多可达环的最大数量。
 *
 * 此函数调用多消费者或单消费者版本，具体取决于在环创建时指定的默认行为（请参阅rte_ring_create传入的flag参数，第四个参数）。
 *
 * @param r
 *   指向环结构的指针。
 * @param obj_table
 *   指向 void * 指针，即待出队对象数组的指针(将被填充)。
 * @param n
 *   obj_table 的数量即从环中取出的对象数量。
 * @param free_space
 *  如果非 NULL，则返回出队完成后剩余的环条目数。
 * @return
 *   - n: 出队对象的实际数量。
 */
to_write = rte_ring_dequeue_burst(recv_ring, (void*)dequeued,
    DPDKCAP_WRITE_BURST_SIZE, NULL);
// 出队的api同样有显式指定是否多生产者安全的api，入参和返回值和rte_ring_dequeue_burst一致

// // 出队函数，非多消费者安全
static __rte_always_inline unsigned
rte_ring_sc_dequeue_burst(struct rte_ring *r, void **obj_table,
		unsigned int n, unsigned int *available)

// 出队函数，多消费者安全(多线程安全)
static __rte_always_inline unsigned
rte_ring_mc_dequeue_burst(struct rte_ring *r, void **obj_table,
		unsigned int n, unsigned int *available);
```

# 总结

dpdk用户常用api分为5大部分

1. eal初始化
2. 内存池创建
3. 端口初始化一系列函数
4. 收发包函数
5. 队列相关函数

熟悉这5大api，将netmap，pcap作为包io的项目改造为使用dpdk将非常容易。