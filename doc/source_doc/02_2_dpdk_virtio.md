# DPDK中虚拟网卡初始化与收发包分析

DPDK通过`virtio`和`vhost PMD`来实现IO的半虚拟化功能，virtio 是 dpdk 虚拟网卡的典型示例，本文将分析下 virtio 的内部原理。

virtio是一种半虚拟化的设备抽象接口规范，在guest操作系统中实现的前端驱动程序一般直接称为virtio，在host操作系统实现的后端驱动程序通常称为vhost。与guest端纯软件模拟I/O（如e1000,rt18139）相比，virtio可以提供很好的I/O性能，虽然同I/O透传技术或者SR-IOV技术相比，目前在网络吞吐率、时延以及抖动性各方面相比都不具备优势，但是其适用性更广且DPDK有针对于SR-IOV的优化正在不断迭代。此外，使用virtio技术可以支持虚拟机的动态迁移以及灵活的流分类规则。

virtio主要有两个版本，0.95和1.0，其规定的实现接口有PCI，MMIO和Channel IO方式，其中Channel IO方式是在1.0版本中新增的。
virtio 使用 virtqueue 来实现其 I/O 机制，每个 virtqueue 就是一个承载大量数据的 queue。vring 是 virtqueue 的具体实现方式，针对 vring 会有相应的描述符表格进行描述。框架如下图所示：

![](resource/virtio.png)

其中比较重要的几个概念是：

- 设备的配置：初始化、配置PCI设备空间和特性、中断配置和专属配置
- 虚拟队列的配置：virtqueue、vring、descriptor table、avaliable ring和used ring的使用
- 设备的使用
- 驱动向设备提供缓冲区并写入数据
- 设备使用数据及归还缓冲区

## 1.DPDK对virtio的实现

virtio在linux内核和dpdk都有相应的驱动，其中linux内核版本功能更加全面，dpdk版本更注重性能。可以先参考下内核中对virtio的实现抽象层次：

- 第一层抽象：底层PCI-e设备层，负责检测PCI-e设备，并初始化设备对应的驱动程序,提供两个抽象类:`virtio_driver`和`virtio_device`
- 第二层抽像：中间virio虚拟队列层，实现`virtqueue`，提供类：`vring_virtqueue`,`vring`等
- 第三层抽象：上层网络设备层，实现底层的两个抽象类:`virtio_net_driver`和`dev`,能够供应用软件将其看成普通的网口使用

对应的dpdk驱动也是按照这个思路来进行实现的。

在dpdk中第一层抽象对应的结构体是是`rte_pci_device`和`rte_pci_driver`。

第二层抽象对应的结构体是:`virtqueue`，`vring`等几乎和内核名字一致。

第三层抽象是`rte_vdev_driver`->`rte_eth_dev`。这一块实现非常多，比如vhost-user的probe代码在`virtio_user_ethdev.c`。

```c
static struct rte_vdev_driver virtio_user_driver = {
	.probe = virtio_user_pmd_probe,
	.remove = virtio_user_pmd_remove,
};
```

这里不同的实现代码不同。vhost为:

```c
static struct rte_vdev_driver pmd_vhost_drv = {
	.probe = rte_pmd_vhost_probe,
	.remove = rte_pmd_vhost_remove,
};
```

## 2.第一层抽象

第一层抽象为DPDK对于PCI-E设备的抽象。

### 2.1 virtio_pci.h

这里的代码类似于`ixgbe_type.h`往往是厂商提供的，具体来讲就是一款网卡芯片的各个寄存器的地址等(相当于是对于网卡芯片手册的代码版)。

这里分为三大模块:

1. virtio设备的配置相关宏定义
2. 相关数据结构，主要是对设备的配置相关(前面两部分参考virtio标准文档)
3. 函数声明，对外提供的操作接口(这部分是DPDK自己实现的)

完整注释版基于19.08的代码在 [virtio_pci.h](src/virtio_pci.h) 。所有代码都是dpdk中摘抄的，没做任何改动。

关于实现这块没有太多需要解释的，主要是针对头文件中定义的相关函数和操作进行实现，需要注意的是需要区分legacy和modern两种版本，下面简单看一个函数具体实现。

### 2.2 virtio_pci.c

同样注释版代码在 [virtio_pci.c](src/virtio_pci.c)

这里需要讲解一个关键函数`vtpci_init`

```c
/*
 * Return -1:
 *   if there is error mapping with VFIO/UIO.
 *   if port map error when driver type is KDRV_NONE.
 *   if whitelisted but driver type is KDRV_UNKNOWN.
 * Return 1 if kernel driver is managing the device.
 * Return 0 on success.
 */
int
vtpci_init(struct rte_pci_device *dev, struct virtio_hw *hw)
{
	/*
	 * Try if we can succeed reading virtio pci caps, which exists
	 * only on modern pci device. If failed, we fallback to legacy
	 * virtio handling.
	 */
	if (virtio_read_caps(dev, hw) == 0) {
		PMD_INIT_LOG(INFO, "modern virtio pci detected.");
		virtio_hw_internal[hw->port_id].vtpci_ops = &modern_ops;
		hw->modern = 1;
		return 0;
	}
    /*如果失败，就尝试绑定legacy操作*/
	PMD_INIT_LOG(INFO, "trying with legacy virtio pci.");
	if (rte_pci_ioport_map(dev, 0, VTPCI_IO(hw)) < 0) {
		rte_pci_unmap_device(dev);
        //跳过内核管理的virtio
		if (dev->kdrv == RTE_KDRV_UNKNOWN &&
		    (!dev->device.devargs ||
		     dev->device.devargs->bus !=
		     rte_bus_find_by_name("pci"))) {
			PMD_INIT_LOG(INFO,
				"skip kernel managed virtio device.");
			return 1;
		}
		return -1;
	}

	virtio_hw_internal[hw->port_id].vtpci_ops = &legacy_ops;
	hw->modern   = 0;

	return 0;
}
```

这个函数实现了自动检测并绑定相应驱动的操作，优先绑定modern virtio。如果modern绑定失败尝试绑定legacy。

怎么写驱动可以参考如下:


```c
// 略
// modern virtio的ops注册
const struct virtio_pci_ops modern_ops = {
	.read_dev_cfg	= modern_read_dev_config,
	.write_dev_cfg	= modern_write_dev_config,
	.get_status	= modern_get_status,
	.set_status	= modern_set_status,
	.get_features	= modern_get_features,
	.set_features	= modern_set_features,
	.get_isr	= modern_get_isr,
	.set_config_irq	= modern_set_config_irq,
	.set_queue_irq  = modern_set_queue_irq,
	.get_queue_num	= modern_get_queue_num,
	.setup_queue	= modern_setup_queue,
	.del_queue	= modern_del_queue,
	.notify_queue	= modern_notify_queue,
};
```

ops的具体实现就是函数指针所等于的函数，基本上来说照搬virtio的标准文档即可。

## 3.第二层抽象

本层中比较重要的数据结构是vring,virtqueue。数据包就是由这两个结构承载的。

### 3.1 vring.h

代码路径为drivers/net/virtio/virtio_ring.h

vring的基础数据结构:

```c
/* 每个描述符代表guest侧的一个数据缓冲区，供guest和host传递数据。
 * 如果要传递的数据大于一个desc的容量，可以包含多个desc，由next串起来
 */
struct vring_desc {
	uint64_t addr;  /*  Address (guest-physical). */
	uint32_t len;   /* Length. */
	uint16_t flags; /* The flags as indicated above. */
	uint16_t next;  /* We chain unused descriptors via this. */
};

struct vring_avail {
	uint16_t flags;
	uint16_t idx;
	uint16_t ring[0];
};

/* id is a 16bit index. uint32_t is used here for ids for padding reasons. */
struct vring_used_elem {
	/* Index of start of used descriptor chain. */
	uint32_t id;
	/* Total length of the descriptor chain which was written to. */
	uint32_t len;
};
```

vring：

```c
// vring的布局：num个vring_desc + available ring size + pad + used ring size
struct vring {
	unsigned int num;
	struct vring_desc  *desc;
	struct vring_avail *avail;
	struct vring_used  *used;
};
```

实际上等价于如下注释中的结构:

```c
/* The standard layout for the ring is a continuous chunk of memory which
 * looks like this.  We assume num is a power of 2.
 *
 * struct vring {
 *      // The actual descriptors (16 bytes each)
 *      struct vring_desc desc[num];
 *
 *      // A ring of available descriptor heads with free-running index.
 *      __u16 avail_flags;
 *      __u16 avail_idx;
 *      __u16 available[num];
 *      __u16 used_event_idx;
 *
 *      // Padding to the next align boundary.
 *      char pad[];
 *
 *      // A ring of used descriptor heads with free-running index.
 *      __u16 used_flags;
 *      __u16 used_idx;
 *      struct vring_used_elem used[num];
 *      __u16 avail_event_idx;
 * };
 *
 * NOTE: for VirtIO PCI, align is 4096.
 */
```

vring结构实际上即为如下:

```c
 struct vring {
      // The actual descriptors (16 bytes each)
      struct vring_desc desc[num];

      /*可用环表，由驱动提供(写入)，设备使用(读取)。*/
      __u16 avail_flags;
      __u16 avail_idx;
      __u16 available[num];
      __u16 used_event_idx;

     // Padding to the next align boundary.
      char pad[];

      /*已用环表，由设备提供(写入)，驱动使用（读取）*/
      __u16 used_flags;
     __u16 used_idx;
      struct vring_used_elem used[num];
      __u16 avail_event_idx;
 };
```

vring大小计算公式:

```c
/*vring size的计算公式*/
static inline size_t
vring_size(unsigned int num, unsigned long align)
{
	size_t size;

	size = num * sizeof(struct vring_desc);
	size += sizeof(struct vring_avail) + (num * sizeof(uint16_t));
	size = RTE_ALIGN_CEIL(size, align);
	size += sizeof(struct vring_used) +
		(num * sizeof(struct vring_used_elem));
	return size;
}
```

关于available ring和used ring中的flags字段，需要特别解释下：
- available ring flag：该环中的desc可能是可读，也可能是可写的。可写的是指驱动提供给设备的desc，供设备写入后还需要传回给驱动；可读的则是用于发送驱动的数据到设备中。flag可以用来标示设备在使用了desc后是否发送中断给驱动。
- used ring flag:表示已用环表的一些属性，包括是否需要驱动在回收了已用环表中的表项后发送提醒给设备。

### 3.2 virtqueue.h

代码在DPDK源码中路径为drivers/net/virtqueue.h。

virtqueue数据结构:

```c
struct virtqueue {
	// 省略
	/* 用途，是收包，发包还是控制通道？*/
	union {
		struct virtnet_rx rxq;
		struct virtnet_tx txq;
		struct virtnet_ctl cq;
	};
	// 省略
};
```

要搞清楚virtqueue作为数据包的载体关键在于跟踪其union结构:

```c
	union {
		struct virtnet_rx rxq;
		struct virtnet_tx txq;
		struct virtnet_ctl cq;
	};
```

其中`rxq`即为接收队列。接着可以看到DPDK的virtio驱动probe函数:

```c
/*
 * dev_ops for virtio, bare necessities for basic operation
 */
static const struct eth_dev_ops virtio_eth_dev_ops ;
```

里面针对rx队列的初始化`virtio_dev_configure`函数内部，实质上就是`rxq`的初始化。

每个设备(`virtio_hw`)拥有多个 `virtqueue` 用于大块数据的传输。

其表现形式代码里很明确:

```c
struct virtio_hw {
	// 省略
	struct virtqueue **vqs; // 这个字段就是设备所拥有的所有virtqueue,是二维数组的原因在于virtqueue有收发的类型
};
```


`virtqueue` 是一个简单的队列（其中包括vring），guest 把 buffers 插入其中，每个 buffer 都是一个分散-聚集数组。virtqueue 的数目根据设备的不同而不同，例如network 设备通常有 2 个 virtqueue,一个用于发送数据包，一个用于接收数据包。

上述所有带有注释的代码可以在 [virtio_ring](src/virtio_ring.h) 和 [vritqueue.h](src/virtqueue.h)。请自行查阅。


## 4.第三层抽象

第三层抽象其实就是虚拟网卡操作函数的抽象，DPDK有不少进行网卡操作的功能放在rte_ethdev.c和rte_ethdev.h中。相对应的virtio也需要提供这些操作。

这一层实质上实现virtio设备以及对virtio设备的各种操作函数。对virtio设备的初始化配置以及特性设置主要集中在virtio_ethdev.c中实现。

这一步的实现代码比较多，仅罗列一些比较重要的，感兴趣的可深入阅读相关接口。

### 4.1初始化

virtio设备初始化最重要的是如下三个函数。

```c
/*驱动初始化virtio设备
* 重新设置rte_eth_dev结构及特性，最大化共用基础结构，而没有重新定义一个virtio dev structure
* 在这个接口里还会和host进行feature的协商，为device申请分配virtqueue，配置中断等等
*/
int
eth_virtio_dev_init(struct rte_eth_dev *eth_dev);
/*为device分配virtqueue，首先获取支持的最大队列，再对每个队列执行初始化*/
static int
virtio_alloc_queues(struct rte_eth_dev *dev);
/*具体的一个队列初始化函数，在这个函数里会区分队列类型，是收包，发包还是控制队列*/
static int
virtio_init_queue(struct rte_eth_dev *dev, uint16_t vtpci_queue_idx)
```

```c
 	/*另外比较重要的是，通过以上初始话过程，会赋值设备的dev_ops,rx_pkt_burst,tx_pkt_burst*/
	eth_dev->dev_ops = &virtio_eth_dev_ops;
	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		if (!hw->virtio_user_dev) {
			ret = virtio_remap_pci(RTE_ETH_DEV_TO_PCI(eth_dev), hw);
			if (ret)
				return ret;
		}

		virtio_set_vtpci_ops(hw);
		set_rxtx_funcs(eth_dev); // 根据特性赋值设备的rx_pkt_burst,tx_pkt_burst即设置收发包函数

		return 0;
	}
```

实际上收发包行为注册在`set_rxtx_funcs`函数中。

收发包行为实际注册如下:

```c
/* set rx and tx handlers according to what is supported */
static void
set_rxtx_funcs(struct rte_eth_dev *eth_dev)
{
	struct virtio_hw *hw = eth_dev->data->dev_private;

	eth_dev->tx_pkt_prepare = virtio_xmit_pkts_prepare;
	if (vtpci_packed_queue(hw)) {
		PMD_INIT_LOG(INFO,
			"virtio: using packed ring %s Tx path on port %u",
			hw->use_inorder_tx ? "inorder" : "standard",
			eth_dev->data->port_id);
		eth_dev->tx_pkt_burst = virtio_xmit_pkts_packed;
	} else {
		if (hw->use_inorder_tx) {
			PMD_INIT_LOG(INFO, "virtio: using inorder Tx path on port %u",
				eth_dev->data->port_id);
			eth_dev->tx_pkt_burst = virtio_xmit_pkts_inorder;
		} else {
			PMD_INIT_LOG(INFO, "virtio: using standard Tx path on port %u",
				eth_dev->data->port_id);
			eth_dev->tx_pkt_burst = virtio_xmit_pkts; // 普通发包函数
		}
	}

	if (vtpci_packed_queue(hw)) {
		if (vtpci_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF)) {
			PMD_INIT_LOG(INFO,
				"virtio: using packed ring mergeable buffer Rx path on port %u",
				eth_dev->data->port_id);
			eth_dev->rx_pkt_burst =
				&virtio_recv_mergeable_pkts_packed;
		} else {
			PMD_INIT_LOG(INFO,
				"virtio: using packed ring standard Rx path on port %u",
				eth_dev->data->port_id);
			eth_dev->rx_pkt_burst = &virtio_recv_pkts_packed;
		}
	} else {
		if (hw->use_simple_rx) {
			PMD_INIT_LOG(INFO, "virtio: using simple Rx path on port %u",
				eth_dev->data->port_id);
			eth_dev->rx_pkt_burst = virtio_recv_pkts_vec; // 使用向量化收发包函数
		} else if (hw->use_inorder_rx) {
			PMD_INIT_LOG(INFO,
				"virtio: using inorder Rx path on port %u",
				eth_dev->data->port_id);
			eth_dev->rx_pkt_burst =	&virtio_recv_pkts_inorder;
		} else if (vtpci_with_feature(hw, VIRTIO_NET_F_MRG_RXBUF)) {
			PMD_INIT_LOG(INFO,
				"virtio: using mergeable buffer Rx path on port %u",
				eth_dev->data->port_id);
			eth_dev->rx_pkt_burst = &virtio_recv_mergeable_pkts; // mergeable可合并缓冲区收包函数
		} else {
			PMD_INIT_LOG(INFO, "virtio: using standard Rx path on port %u",
				eth_dev->data->port_id);
			eth_dev->rx_pkt_burst = &virtio_recv_pkts; // 普通收包函数
		}
	}

}
```

设备初始化好后，virtio设备的使用主要包括两部分：驱动通过描述符列表和可用环表提供数据缓冲区给设备，设备使用数据缓冲区再通过已用环表还给驱动。以网卡为例：网络设备一般有两个vq：发包队列和接收队列。驱动添加要发送的包到发送队列，然后设备读取并发送完成后，驱动再释放这些包。反方向，设备将包写入到接收队列中，驱动则在已用环表中处理这些包。

### 4.2virtio_rxtx.c

接着看普通收包函数: `virtio_recv_pkts`，这里dpdk还提供了一个向量化版本`virtio_recv_pkts_vec`。

只看关键点:

```c
uint16_t
virtio_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	// 省略
	// 加锁
	virtio_rmb(hw->weak_barriers);

	num = likely(nb_used <= nb_pkts) ? nb_used : nb_pkts;
	if (unlikely(num > VIRTIO_MBUF_BURST_SZ))
		num = VIRTIO_MBUF_BURST_SZ;
	if (likely(num > DESC_PER_CACHELINE))
		num = num - ((vq->vq_used_cons_idx + num) % DESC_PER_CACHELINE);
	/* 驱动一次性从收包队列中获取num个报文，实际上是读取已用环表获取描述符，
	*  读取完成后需要释放desc到free chain中
	*/
	num = virtqueue_dequeue_burst_rx(vq, rcv_pkts, len, num);
	PMD_RX_LOG(DEBUG, "used:%d dequeue:%d", nb_used, num);

	nb_enqueued = 0;
	hdr_size = hw->vtnet_hdr_size;
	/* 将前面读出来的报文赋值到二级指针rx_pkts中 */
	for (i = 0; i < num ; i++) {
		rxm = rcv_pkts[i];

		PMD_RX_LOG(DEBUG, "packet len:%d", len[i]);

		if (unlikely(len[i] < hdr_size + RTE_ETHER_HDR_LEN)) {
			PMD_RX_LOG(ERR, "Packet drop");
			nb_enqueued++;
			virtio_discard_rxbuf(vq, rxm);
			rxvq->stats.errors++;
			continue;
		}

		rxm->port = rxvq->port_id;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->ol_flags = 0;
		rxm->vlan_tci = 0;

		rxm->pkt_len = (uint32_t)(len[i] - hdr_size);
		rxm->data_len = (uint16_t)(len[i] - hdr_size);

		hdr = (struct virtio_net_hdr *)((char *)rxm->buf_addr +
			RTE_PKTMBUF_HEADROOM - hdr_size);

		if (hw->vlan_strip)
			rte_vlan_strip(rxm);

		if (hw->has_rx_offload && virtio_rx_offload(rxm, hdr) < 0) {
			virtio_discard_rxbuf(vq, rxm);
			rxvq->stats.errors++;
			continue;
		}
		/* 更新收包信息 */
		virtio_rx_stats_updated(rxvq, rxm);
		/* 把报文dump出来到rx_pkts */
		rx_pkts[nb_rx++] = rxm;
	}

	rxvq->stats.packets += nb_rx;
	/* 重新对used descriptor分配mbuf，并插入到可用队列中 */
	/* Allocate new mbuf for the used descriptor */
	if (likely(!virtqueue_full(vq))) {
		uint16_t free_cnt = vq->vq_free_cnt;
		struct rte_mbuf *new_pkts[free_cnt];

		if (likely(rte_pktmbuf_alloc_bulk(rxvq->mpool, new_pkts,
						free_cnt) == 0)) {
			error = virtqueue_enqueue_recv_refill(vq, new_pkts,
					free_cnt);
			if (unlikely(error)) {
				for (i = 0; i < free_cnt; i++)
					rte_pktmbuf_free(new_pkts[i]);
			}
			nb_enqueued += free_cnt;
		} else {
			struct rte_eth_dev *dev =
				&rte_eth_devices[rxvq->port_id];
			dev->data->rx_mbuf_alloc_failed += free_cnt;
		}
	}
	/* 可用队列更新后，要通知host端设备 */
	if (likely(nb_enqueued)) {
		vq_update_avail_idx(vq);

		if (unlikely(virtqueue_kick_prepare(vq))) {
			virtqueue_notify(vq);
			PMD_RX_LOG(DEBUG, "Notified");
		}
	}

	return nb_rx;
}
```

`virtio_recv_pkts_vec`则是向量化版本，其中sse的向量化版本在 drivers\net\virtio\virtio_rxtx_simple_sse.c 可以自行阅读。

题外话:看到这部分的时候很敬佩DPDK的开发，DPDK之所以快核心在于能优化的点都去尝试。

接下来可以看发包函数`virtio_xmit_pkts`的关键代码:

这里要明确一点实际的发包函数其实是`virtqueue_enqueue_xmit`。

```c
uint16_t
virtio_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	// ......
	/* 加锁 */
	virtio_rmb(hw->weak_barriers);
	/* 如果已用环表空间不足，将已经传输完成的释放掉 */
	if (likely(nb_used > vq->vq_nentries - vq->vq_free_thresh))
		virtio_xmit_cleanup(vq, nb_used);

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		struct rte_mbuf *txm = tx_pkts[nb_tx];
		int can_push = 0, use_indirect = 0, slots, need;

		/* ...... */

		/* 实际的发包函数，将txm中的数据通过txvq发送出去 */
		/* Enqueue Packet buffers */
		virtqueue_enqueue_xmit(txvq, txm, slots, use_indirect,
			can_push, 0);

		virtio_update_packet_stats(&txvq->stats, txm);
	}

	txvq->stats.packets += nb_tx;
	/* 通知host */
	if (likely(nb_tx)) {
		vq_update_avail_idx(vq); // 把缓存内容放入desc中，更新可用环表

		if (unlikely(virtqueue_kick_prepare(vq))) {
			virtqueue_notify(vq);
			PMD_TX_LOG(DEBUG, "Notified backend after xmit");
		}
	}

	return nb_tx;
}
```

实际发包函数`virtqueue_enqueue_xmit`详解:

```c
static inline void
virtqueue_enqueue_xmit(struct virtnet_tx *txvq, struct rte_mbuf *cookie,
			uint16_t needed, int use_indirect, int can_push,
			int in_order)
{
	// ......

	do {
		start_dp[idx].addr  = VIRTIO_MBUF_DATA_DMA_ADDR(cookie, vq);
		start_dp[idx].len   = cookie->data_len;
		start_dp[idx].flags = cookie->next ? VRING_DESC_F_NEXT : 0;
		idx = start_dp[idx].next;
	} while ((cookie = cookie->next) != NULL);

	if (use_indirect)
		idx = vq->vq_split.ring.desc[head_idx].next;

	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - needed);

	vq->vq_desc_head_idx = idx;
	vq_update_avail_ring(vq, head_idx); //把cookie内容放入desc中，更新可用环表

	if (!in_order) {
		if (vq->vq_desc_head_idx == VQ_RING_DESC_CHAIN_END)
			vq->vq_desc_tail_idx = idx;
	}
}
```

上述的带注释的代码 [virtio_ethdev.h](src/virtio_ethdev.h) , [virtio_ethdev.c](src/virtio_ethdev.c) , [virtio_rxtx.h](src/virtio_rxtx.h) , [virtio_rxtx.c](src/virtio_rxtx.c)。

# 总结

DPDK中的虚拟网卡收发包和内核实现类似，分为三层抽象:

1. 第一层抽象实现了虚拟网卡的驱动
2. 第二层抽象实现了vring,virtqueue
3. 第三层抽象就是实际的收发包，初始化等功能。实现了驱动要绑定的相关操作。