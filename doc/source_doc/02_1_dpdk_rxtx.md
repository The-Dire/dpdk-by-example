# DPDK物理网卡收发包实现分析

DPDK收发包是基础核心模块，从网卡收到包到驱动把包拷贝到系统内存中，再到系统对这块数据包的内存管理，由于在处理过程中实现了零拷贝，数据包从接收到发送始终只有一份，本文主要介绍收发包的过程。

简言之，**dpdk使用dma方式将收到的报文保存在事先分配好的mbuf里面，收发报文时零拷贝。**具体是怎么实现零拷贝的呢。主要的就是**配置网卡的收发队列描述符**，**设置网卡DMA拷贝数据包的目的地址为mbuf的物理地址**，配置好地址后，网卡收到数据包后会通过DMA控制器直接把数据包拷贝到指定的内存地址。

从这里可以看出:DPDK根本优势是去除了内核与应用程序的区分，从而消除了二者交互带来的开销，即数据拷贝开销与软中断开销。

下面分析收发包细节。

## 1.收发包阶段总览

收发包过程大致可以分为2个部分：

1. 收发包的配置和初始化，主要是配置收发队列等。
2. 数据包的获取和发送，主要是从队列中获取到数据包或者把数据包放到队列中。

## 2.收发包的配置和初始化

收发包的配置最主要的工作就是配置网卡的收发队列，设置DMA拷贝数据包的地址等，配置好地址后，网卡收到数据包后会通过DMA控制器直接把数据包拷贝到指定的内存地址。需要使用数据包时，只要去对应队列取出指定地址的数据即可。

收发包的配置是从`rte_eth_dev_configure()`开始的，这里根据参数会配置队列的个数，以及接口的配置信息，如队列的使用模式，多队列的方式等。

代码逻辑是: 先进行一些各项检查，如果设备已经启动，就得先停止才能进行配置（再配置）。然后把传进去的配置参数拷贝到设备的数据区。



`rte_eth_dev_configure()`核心逻辑解析如下:

```c
    // 1. 存储设备的原始配置
	 /* Store original config, as rollback required on failure */
	memcpy(&orig_conf, &dev->data->dev_conf, sizeof(dev->data->dev_conf));

	/*
	 * Copy the dev_conf parameter into the dev structure.
	 * rte_eth_dev_info_get() requires dev_conf, copy it before dev_info get
	 */
     // 2. 配置参数拷贝到设备的数据区
	memcpy(&dev->data->dev_conf, dev_conf, sizeof(dev->data->dev_conf));
    // 3. 获取设备的信息,实际调用是(*dev->dev_ops->dev_infos_get)(dev, dev_info);
    rte_eth_dev_info_get(port_id, &dev_info);
```

注: 获取设备的信息的主要作用是为了后面的检测。

这里的`dev_infos_get`是在驱动初始化过程中设备初始化时配置的(`eth_ixgbe_dev_init()`)

`eth_dev->dev_ops = &ixgbe_eth_dev_ops;`重要的信息检查过后，下面就是对发送和接收队列进行配置。

先看接收队列的配置，接收队列是从`rte_eth_dev_tx_queue_config()`开始的 在接收配置中，考虑的是有两种情况，一种是第一次配置；另一种是重新配置。所以，代码中都做了区分。

1. 如果是第一次配置，那么就为每个队列分配一个指针。 
2. 如果是重新配置，配置的queue数量不为0，那么就取消之前的配置，重新配置。
3. 如果是重新配置，但要求的queue为0，那么释放已有的配置。

这部分源码非常简单，就不过多赘述了。

发送的配置也是同样的，在`rte_eth_dev_tx_queue_config()`函数中。

当收发队列配置完成后，就调用设备的配置函数，进行最后的配置。

在`rte_eth_dev_configure()`中调用`diag = (*dev->dev_ops->dev_configure)(dev);`，以ixgbe为例对应的配置函数为`ixgbe_dev_configure()`，进入`ixgbe_dev_configure()`来分析其过程,其实这个函数并没有做太多的事。

在函数中，先调用了`ixgbe_check_mq_mode()`来检查队列的模式。

检测通过则设置允许为接收批量和向量的模式，设置如下:

```c
adapter->rx_bulk_alloc_allowed = true;
adapter->rx_vec_allowed = true;
```

完整代码如下:

```c
static int
ixgbe_dev_configure(struct rte_eth_dev *dev)
{
	struct ixgbe_interrupt *intr =
		IXGBE_DEV_PRIVATE_TO_INTR(dev->data->dev_private);
	struct ixgbe_adapter *adapter = dev->data->dev_private;
	int ret;

	PMD_INIT_FUNC_TRACE();
	/* multipe queue mode checking 队列模式检测 */
	ret  = ixgbe_check_mq_mode(dev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "ixgbe_check_mq_mode fails with %d.",
			    ret);
		return ret;
	}
    // 更新链路状态
	/* set flag to update link status after init */
	intr->flags |= IXGBE_FLAG_NEED_LINK_UPDATE;

	/*
	 * Initialize to TRUE. If any of Rx queues doesn't meet the bulk
	 * allocation or vector Rx preconditions we will reset it.
	 */
	adapter->rx_bulk_alloc_allowed = true;
	adapter->rx_vec_allowed = true;

	return 0;
}
```

上面相当于是弄完了收发队列的配置，接着才是根据队列进行初始化操作。

## 3.接收队列的初始化

接收队列的初始化是从`rte_eth_rx_queue_setup()`开始的，这里的参数需要指定要初始化的port_id,queue_id,以及描述符的个数，还可以指定接收的配置，如释放和回写的阈值等。

依然如其他函数的套路一样，先进行各种检查，如初始化的队列号是否合法有效，设备如果已经启动，就不能继续初始化了。检查函数指针是否有效等。检查mbuf的数据大小是否满足默认的设备信息里的配置。

`rte_eth_dev_info_get(port_id, &dev_info);`

这里获取了设备的配置信息，如果调用初始化函数时没有指定rx_conf配置，就会设备配置信息里的默认值。

```c
// 以ixgbe为例其default_rxconf为如下
dev_info->default_rxconf = (struct rte_eth_rxconf) {
        .rx_thresh = {
            .pthresh = IXGBE_DEFAULT_RX_PTHRESH,
            .hthresh = IXGBE_DEFAULT_RX_HTHRESH,
            .wthresh = IXGBE_DEFAULT_RX_WTHRESH,
        },
        .rx_free_thresh = IXGBE_DEFAULT_RX_FREE_THRESH,
        .rx_drop_en = 0,
    };
```

接着就进入了rx队列的实际初始化流程,

还检查了要初始化的队列号对应的队列指针是否为空，如果不为空，则说明这个队列已经初始化过了，就释放这个队列。

```c
	rxq = dev->data->rx_queues;
	if (rxq[rx_queue_id]) {
		RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->rx_queue_release,
					-ENOTSUP);
		(*dev->dev_ops->rx_queue_release)(rxq[rx_queue_id]);
		rxq[rx_queue_id] = NULL;
	}
```

最后，调用到队列的setup函数做最后的初始化。

```c
	ret = (*dev->dev_ops->rx_queue_setup)(dev, rx_queue_id, nb_rx_desc,
					      socket_id, &local_conf, mp);

```
对于ixgbe设备，`rx_queue_setup`就是函数`ixgbe_dev_rx_queue_setup()`，这里就是网卡队列实际的初始化函数(对设备启作用的初始化)。

依然是先检查，检查描述符的数量最大不能大于IXGBE_MAX_RING_DESC个，最小不能小于IXGBE_MIN_RING_DESC个。

```c
	/*
	 * Validate number of receive descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of IXGBE_ALIGN.
	 */
	if (nb_desc % IXGBE_RXD_ALIGN != 0 ||
			(nb_desc > IXGBE_MAX_RING_DESC) ||
			(nb_desc < IXGBE_MIN_RING_DESC)) {
		return -EINVAL;
	}

```

接下来是重点：

1. 分配队列结构体，并填充结构

```c
// 同样有队列不为空则释放的逻辑
if (dev->data->rx_queues[queue_idx] != NULL) {
    ixgbe_rx_queue_release(dev->data->rx_queues[queue_idx]);
    dev->data->rx_queues[queue_idx] = NULL;
}
// 分配队列结构体
rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct ixgbe_rx_queue),
                 RTE_CACHE_LINE_SIZE, socket_id);
```
填充结构体的所属内存池，描述符个数，队列号，队列所属接口号等成员。

3. 分配描述符队列的空间，按照最大的描述符个数进行分配

```c
rz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx,
                      RX_RING_SZ, IXGBE_ALIGN, socket_id);
```

接着获取描述符队列的头和尾寄存器的地址，在收发包后，软件要对这个寄存器进行处理。关注`rdt_reg_addr`和`rdh_reg_addr`就能明白数据包是怎么通过驱动到应用程序的。

```c
	/*
	 * Modified to setup VFRDT for Virtual Function
	 */
	if (hw->mac.type == ixgbe_mac_82599_vf ||
	    hw->mac.type == ixgbe_mac_X540_vf ||
	    hw->mac.type == ixgbe_mac_X550_vf ||
	    hw->mac.type == ixgbe_mac_X550EM_x_vf ||
	    hw->mac.type == ixgbe_mac_X550EM_a_vf) {
		rxq->rdt_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_VFRDT(queue_idx));
		rxq->rdh_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_VFRDH(queue_idx));
	} else {
		rxq->rdt_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_RDT(rxq->reg_idx));
		rxq->rdh_reg_addr =
			IXGBE_PCI_REG_ADDR(hw, IXGBE_RDH(rxq->reg_idx));
	}
```

设置队列的接收描述符ring的物理地址和虚拟地址。
```c
	rxq->rx_ring_phys_addr = rz->iova;
	rxq->rx_ring = (union ixgbe_adv_rx_desc *) rz->addr;
```


3. 分配sw_ring，这个ring中存储的对象是struct ixgbe_rx_entry，其实里面就是数据包mbuf的指针。

```c
	rxq->sw_ring = rte_zmalloc_socket("rxq->sw_ring",
					  sizeof(struct ixgbe_rx_entry) * len,
					  RTE_CACHE_LINE_SIZE, socket_id);
```
以上三步做完以后，新分配的队列结构体重要的部分就已经填充完了，下面需要重置一下其他成员。

```c
ixgbe_reset_rx_queue()
```

先把分配的描述符队列清空，其实清空在分配的时候就已经做了，这里重复做的原因未知。

```c
	for (i = 0; i < len; i++) {
		rxq->rx_ring[i] = zeroed_desc;
	}
```

然后初始化队列中一下其他成员

```c
	rxq->rx_nb_avail = 0;
	rxq->rx_next_avail = 0;
	rxq->rx_free_trigger = (uint16_t)(rxq->rx_free_thresh - 1);
	rxq->rx_tail = 0;
	rxq->nb_rx_hold = 0;
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;

#ifdef RTE_IXGBE_INC_VECTOR
	rxq->rxrearm_start = 0;
	rxq->rxrearm_nb = 0;
#endif
```

这样，接收队列就初始化完了。

## 4.发送队列初始化

发送队列的初始化在前面的检查基本和接收队列一样，只有些许区别在于setup环节，初始化的入口函数为：`ixgbe_dev_tx_queue_setup()`。

在发送队列配置中，重点设置了`tx_rs_thresh`和`tx_free_thresh`的值。

然后分配了一个发送队列结构txq,之后分配发送队列ring的空间，并填充txq的结构体

```c
    // dpdk 19.08版本,新版本tx ring的物理地址填充更加简单
	txq->tx_ring_phys_addr = tz->iova;
	txq->tx_ring = (union ixgbe_adv_tx_desc *) tz->addr;
    // dpdk 16.04版本
    txq->tx_ring_phys_addr = rte_mem_phy2mch(tz->memseg_id, tz->phys_addr);
    txq->tx_ring = (union ixgbe_adv_tx_desc *) tz->addr;
```

然后，分配队列的sw_ring,也挂载队列上。

重置发送队列
```c
	txq->ops->reset(txq);
```
和接收队列一样，也是要把队列ring（描述符ring）清空，设置发送队列sw_ring,设置其他参数，队尾位置设置为0

```c
/* (Re)set dynamic ixgbe_tx_queue fields to defaults */
static void __attribute__((cold))
ixgbe_reset_tx_queue(struct ixgbe_tx_queue *txq)
{
	static const union ixgbe_adv_tx_desc zeroed_desc = {{0}};
	struct ixgbe_tx_entry *txe = txq->sw_ring;
	uint16_t prev, i;

	/* Zero out HW ring memory */
	for (i = 0; i < txq->nb_tx_desc; i++) {
		txq->tx_ring[i] = zeroed_desc;
	}

	/* Initialize SW ring entries */
	prev = (uint16_t) (txq->nb_tx_desc - 1);
	for (i = 0; i < txq->nb_tx_desc; i++) {
		volatile union ixgbe_adv_tx_desc *txd = &txq->tx_ring[i];

		txd->wb.status = rte_cpu_to_le_32(IXGBE_TXD_STAT_DD);
		txe[i].mbuf = NULL;
		txe[i].last_id = i;
		txe[prev].next_id = i;
		prev = i;
	}

	txq->tx_next_dd = (uint16_t)(txq->tx_rs_thresh - 1);
	txq->tx_next_rs = (uint16_t)(txq->tx_rs_thresh - 1);

	txq->tx_tail = 0;
	txq->nb_tx_used = 0;
	/*
	 * Always allow 1 descriptor to be un-allocated to avoid
	 * a H/W race condition
	 */
	txq->last_desc_cleaned = (uint16_t)(txq->nb_tx_desc - 1);
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_desc - 1);
	txq->ctx_curr = 0;
	memset((void *)&txq->ctx_cache, 0,
		IXGBE_CTX_NUM * sizeof(struct ixgbe_advctx_info));
}
```

发送队列的初始化就完成了。

## 5.启动设备

经过上面的队列初始化，队列的ring和sw_ring(软ring)都分配了，但仍然存在一个问题：DMA仍然还不知道要把数据包拷贝到哪里，DPDK是零拷贝的，那么分配的mempool中的对象怎么和队列以及驱动联系起来呢？

接下来就是DPDK零拷贝比较核心的逻辑了----建立mempool、queue、DMA、ring之间的关系。

从这里可以发现，DPDK启动设备其实就是在做物理地址到程序虚拟地址的映射。

设备的启动是从`rte_eth_dev_start()`中开始的,实际执行如下:

```c
diag = (*dev->dev_ops->dev_start)(dev);
```

以ixgbe为例，设备启动的真正启动函数：`ixgbe_dev_start()`。


1. 先检查设备的链路设置`dev->data->dev_conf.link_speeds & ETH_LINK_SPEED_FIXED`，暂时不支持半双工和固定速率的模式。截止DPDK 19.08都只有自适应模式。
2. 禁用链路设置`rte_eal_alarm_cancel(ixgbe_dev_setup_link_alarm_handler, dev);`。
3. 禁用uio 中断映射轮询`rte_intr_disable(intr_handle);`。
4. 然后把中断禁掉，同时，停掉适配器`ixgbe_stop_adapter(hw);`

```c
s32 ixgbe_stop_adapter(struct ixgbe_hw *hw)
{
	return ixgbe_call_func(hw, hw->mac.ops.stop_adapter, (hw),
			       IXGBE_NOT_IMPLEMENTED);
}

mac->ops.stop_adapter = ixgbe_stop_adapter_generic;
```

在`ixgbe_stop_adapter()`函数内部，可知实际调用了`ixgbe_stop_adapter_generic();`，该函数主要的工作就是停止发送和接收单元。这是直接写寄存器来完成的。

5. 重启硬件，`ixgbe_pf_reset_hw()->ixgbe_reset_hw()->ixgbe_reset_hw_82599()`,最终都是设置寄存器，这里就不细究了。之后，就启动了硬件。
   
6. 接着是一系列配置，
   - 检查以及检查并配置队列 Intr-Vector 映射
   - 配置 msix 以用于睡眠，直到 rx 中断
   - 初始化传输单元。

### 5.1接收单元初始化

7. 初始化接收单元：`ixgbe_dev_rx_init()`

在这个函数中，主要就是设置各类寄存器，比如配置CRC校验，如果支持巨帧，配置对应的寄存器。还有如果配置了loopback模式，也要配置寄存器。
接下来最重要的就是为每个队列设置DMA寄存器，标识每个队列的描述符ring的地址，长度，头，尾等。

```c
/* Setup the Base and Length of the Rx Descriptor Rings */
bus_addr = rxq->rx_ring_phys_addr;
IXGBE_WRITE_REG(hw, IXGBE_RDBAL(rxq->reg_idx),
        (uint32_t)(bus_addr & 0x00000000ffffffffULL));
IXGBE_WRITE_REG(hw, IXGBE_RDBAH(rxq->reg_idx),
        (uint32_t)(bus_addr >> 32));
IXGBE_WRITE_REG(hw, IXGBE_RDLEN(rxq->reg_idx),
        rxq->nb_rx_desc * sizeof(union ixgbe_adv_rx_desc));
IXGBE_WRITE_REG(hw, IXGBE_RDH(rxq->reg_idx), 0);
IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx), 0);
```

这里可以看到把描述符ring的物理地址写入了寄存器，还写入了描述符ring的长度。

8. 接着还计算了数据包数据的长度，写入到寄存器中。最后对于网卡的多队列设置,进行了配置`ixgbe_dev_mq_rx_configure(dev);`。

9. 同时如果设置了接收校验和，还对校验和进行了寄存器设置。

10. 最后，调用`ixgbe_set_rx_function(dev);`对接收函数再进行设置，主要是针对支持LRO，vector,bulk等处理方法。其中最普通的收包函数为:`ixgbe_recv_pkts()`。

这样，接收单元的初始化就完成了。

### 5.2发送单元初始化

接下来再初始化发送单元：`ixgbe_dev_tx_init()`。
发送单元的的初始化和接收单元的初始化基本操作是一样的，都是填充寄存器的值。

12. 重点是设置描述符队列的基地址和长度。

```c
bus_addr = txq->tx_ring_phys_addr;
IXGBE_WRITE_REG(hw, IXGBE_TDBAL(txq->reg_idx),
        (uint32_t)(bus_addr & 0x00000000ffffffffULL));
IXGBE_WRITE_REG(hw, IXGBE_TDBAH(txq->reg_idx),
        (uint32_t)(bus_addr >> 32));
IXGBE_WRITE_REG(hw, IXGBE_TDLEN(txq->reg_idx),
        txq->nb_tx_desc * sizeof(union ixgbe_adv_tx_desc));
/* Setup the HW Tx Head and TX Tail descriptor pointers */
IXGBE_WRITE_REG(hw, IXGBE_TDH(txq->reg_idx), 0);
IXGBE_WRITE_REG(hw, IXGBE_TDT(txq->reg_idx), 0);
```

13. 最后配置一下多队列使用相关的寄存器：`ixgbe_dev_mq_tx_configure()`。

注:发送单元有段逻辑明显不同于接收单元 ： 增加了根据不同的网卡型号进行了禁用 tx 头回写 RO 位的配置。

如此，发送单元的初始化就完成了

### 5.3收发单元启动

收发单元初始化完毕后，就可以启动设备的收发单元：

#### 5.3.1收包启动流程分析

```c
int __attribute__((cold))
ixgbe_dev_rxtx_start(struct rte_eth_dev *dev)
``` 

1. 先对每个发送队列的threshold相关寄存器进行设置，这是发送时的阈值参数。(发送阈值寄存器配置)
2. 依次启动每个接收队列。`ixgbe_dev_rx_queue_start()`

```c
int __attribute__((cold))
ixgbe_dev_rx_queue_start(struct rte_eth_dev *dev, uint16_t rx_queue_id)
{
	struct ixgbe_hw     *hw;
	struct ixgbe_rx_queue *rxq;
	uint32_t rxdctl;
	int poll_ms;

	PMD_INIT_FUNC_TRACE();
	hw = IXGBE_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	rxq = dev->data->rx_queues[rx_queue_id];
    // 1. 先检查，如果要启动的队列是合法的，那么就为这个接收队列分配存放mbuf的实际空间，
	/* Allocate buffers for descriptor rings */
	if (ixgbe_alloc_rx_queue_mbufs(rxq) != 0) {
		PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
			     rx_queue_id);
		return -1;
	}
	rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxq->reg_idx));
	rxdctl |= IXGBE_RXDCTL_ENABLE;
	IXGBE_WRITE_REG(hw, IXGBE_RXDCTL(rxq->reg_idx), rxdctl);
    // 2. 等待直到rx使能模块就绪
	/* Wait until RX Enable ready */
	poll_ms = RTE_IXGBE_REGISTER_POLL_WAIT_10_MS;
	do {
		rte_delay_ms(1);
		rxdctl = IXGBE_READ_REG(hw, IXGBE_RXDCTL(rxq->reg_idx));
	} while (--poll_ms && !(rxdctl & IXGBE_RXDCTL_ENABLE));
	if (!poll_ms)
		PMD_INIT_LOG(ERR, "Could not enable Rx Queue %d", rx_queue_id);
	rte_wmb();
    // 头设置为0
	IXGBE_WRITE_REG(hw, IXGBE_RDH(rxq->reg_idx), 0);
    // 尾设置为描述符个数减1，这样描述符就填满整个ring
	IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx), rxq->nb_rx_desc - 1);
	dev->data->rx_queue_state[rx_queue_id] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}
```

该函数逻辑是先检查，如果要启动的队列是合法的，那么就为这个接收队列分配存放mbuf的实际空间。

```c
if (ixgbe_alloc_rx_queue_mbufs(rxq) != 0) 
{
    PMD_INIT_LOG(ERR, "Could not alloc mbuf for queue:%d",
             rx_queue_id);
    return -1;
}
```

其中`ixgbe_alloc_rx_queue_mbufs`就是ixgbe驱动中DPDK最核心的函数：这个函数把mempool、ring、queue ring、queue sw_ring的联系到了一起。
```c
static int __attribute__((cold))
ixgbe_alloc_rx_queue_mbufs(struct ixgbe_rx_queue *rxq)
{
	struct ixgbe_rx_entry *rxe = rxq->sw_ring;
	uint64_t dma_addr;
	unsigned int i;
    // 初始化软件收包ring实例
    // 1. 从队列所属内存池的ring中循环取出了nb_rx_desc个mbuf指针，也就是为了填充rxq->sw_ring。每个指针都指向内存池里的一个数据包空间。
	/* Initialize software ring entries */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		volatile union ixgbe_adv_rx_desc *rxd;
        // 2. 先填充了新分配的mbuf结构
		struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(rxq->mb_pool); 

		if (mbuf == NULL) {
			PMD_INIT_LOG(ERR, "RX mbuf alloc failed queue_id=%u",
				     (unsigned) rxq->queue_id);
			return -ENOMEM;
		}

		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		mbuf->port = rxq->port_id;
        // 3. 计算对应的dma地址，
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
        // 4. 初始化queue ring，即rxd的信息
		rxd = &rxq->rx_ring[i];
		rxd->read.hdr_addr = 0;
		rxd->read.pkt_addr = dma_addr; // 标明了驱动把数据包放在dma_addr处。
		rxe[i].mbuf = mbuf; // 最后一句，把分配的mbuf“放入”queue 的sw_ring中，这样，驱动收过来的包，就直接放在了sw_ring中。
	}

	return 0;
}
```

`ixgbe_alloc_rx_queue_mbufs()`逻辑总结:
   - 1. 从队列所属内存池的ring中循环取出了nb_rx_desc个mbuf指针，也就是为了填充rxq->sw_ring。每个指针都指向内存池里的一个数据包空间。
   - 2. 然后就先填充了新分配的mbuf结构。
   - 3. **填充计算了dma_addr**，即网卡驱动指示软件收包的地址。
   - 4. 初始化queue ring，即rxd的信息，标明了驱动把数据包放在dma_addr处。最后一句，把分配的mbuf放入queue 的sw_ring中，这样，驱动收过来的包，就直接放在了sw_ring中。



以上最重要的工作就完成了，

接着回到函数`ixgbe_dev_rx_queue_start()`的逻辑。

3. 设置一下队列ring的头尾寄存器的值，这也非常重要。头设置为0，尾设置为描述符个数减1，此时描述符填满整个ring。

```c
IXGBE_WRITE_REG(hw, IXGBE_RDH(rxq->reg_idx), 0);
IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx), rxq->nb_rx_desc - 1);
```

最后回到函数`ixgbe_dev_rxtx_start()`的逻辑。

4. 接着该函数使能DMA引擎，准备收包。

```c
hw->mac.ops.enable_rx_dma(hw, rxctrl);
```

随着这步做完，收包所需的流程就走完了

#### 5.3.2发包启动流程分析

1. 依次启动每个发送队列：

发送队列的启动比接收队列的启动要简单，只是配置了txdctl寄存器，延时等待TX使能完成，最后，设置队列的头和尾位置都为0。

```c
int __attribute__((cold))
ixgbe_dev_tx_queue_start(struct rte_eth_dev *dev, uint16_t tx_queue_id)
{
    IXGBE_WRITE_REG(hw, IXGBE_TDH(txq->reg_idx), 0);
    // 省略

    txdctl = IXGBE_READ_REG(hw, IXGBE_TXDCTL(txq->reg_idx));
    txdctl |= IXGBE_TXDCTL_ENABLE;
    IXGBE_WRITE_REG(hw, IXGBE_TXDCTL(txq->reg_idx), txdctl);

    // 省略配置流程

    IXGBE_WRITE_REG(hw, IXGBE_TDT(txq->reg_idx), 0);
}
```
发送队列就启动完成了。

## 6.收包过程

数据包的获取是指驱动把数据包放入了内存中，上层应用从队列中去取出这些数据包；发送是指把要发送的数据包放入到发送队列中，为实际发送做准备。

这里对于应用程序来说只需要弄明白一件事情:怎么数据包的获取？

业务层面获取数据包是从`rte_eth_rx_burst()`开始的

```c
	uint16_t nb_rx;
	nb_rx = (*dev->rx_pkt_burst)(dev->data->rx_queues[queue_id],
				     rx_pkts, nb_pkts);
```

这里的`dev->rx_pkt_burst`在驱动初始化的时候已经注册过了，对于ixgbe设备，就是`ixgbe_recv_pkts()`函数。

在说收包之前，需要先了解网卡的DD标志，这个标志标识着一个描述符是否可用的情况：网卡在使用这个描述符前，先检查DD位是否为0，如果为0，那么就可以使用描述符，把数据拷贝到描述符指定的地址，之后把DD标志位置为1，否则表示不能使用这个描述符。

而对于驱动而言，恰恰相反，在读取数据包时，先检查DD位是否为1，如果为1，表示网卡已经把数据放到了内存中，可以读取，读取完后，再把DD位设置为0，否则，就表示没有数据包可读。

重点就是`ixgbe_recv_pkts()`这个函数看看，从这个函数可以了解数据包是怎么被取出来的。

下面是函数的精简注释版:

```c
uint16_t
ixgbe_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct ixgbe_rx_queue *rxq;
	volatile union ixgbe_adv_rx_desc *rx_ring;
	volatile union ixgbe_adv_rx_desc *rxdp;
	struct ixgbe_rx_entry *sw_ring;
	struct ixgbe_rx_entry *rxe;
	struct rte_mbuf *rxm;
	struct rte_mbuf *nmb;
	union ixgbe_adv_rx_desc rxd;
	uint64_t dma_addr;
	uint32_t staterr;
	uint32_t pkt_info;
	uint16_t pkt_len;
	uint16_t rx_id;
	uint16_t nb_rx;
	uint16_t nb_hold;
	uint64_t pkt_flags;
	uint64_t vlan_flags;

	nb_rx = 0;
	nb_hold = 0;
	rxq = rx_queue;
	rx_id = rxq->rx_tail; // 标识当前ring的尾
	rx_ring = rxq->rx_ring;
	sw_ring = rxq->sw_ring;
	vlan_flags = rxq->vlan_flags;
    // 循环读取请求数量的描述符
	while (nb_rx < nb_pkts) {
        rxdp = &rx_ring[rx_id];
        // 判断就是这个描述符是否可用
        staterr = rxdp->wb.upper.status_error;
        if (!(staterr & rte_cpu_to_le_32(IXGBE_RXDADV_STAT_DD)))
            break;
        

        // 省略
        // 接下来是狸猫换太子的过程(驱动ring里的描述符变mbuf)
        // 先从mempool的ring中分配一个新的“狸猫”—mbuf
        nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
        // 省略
        // 找到当前描述符对应的“太子”(驱动sw_ring里的数据包描述符)—ixgbe_rx_entry *rxe
        rxe = &sw_ring[rx_id];
        // 省略预取操作
        // rxm的用户的mbuf的地址，需要将其对应到驱动的mbuf地址。
        rxm = rxe->mbuf;
        rxe->mbuf = nmb;
        // 收包后，设置对于描述符清理，rxdp->read.hdr_addr = 0;即是网卡DD位置为0
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb));
		rxdp->read.hdr_addr = 0;
		rxdp->read.pkt_addr = dma_addr;
        // 这样换出来的太子rxm就是我们要取出来的数据包指针，在下面填充一些必要的信息，就可以把包返给接收的用户了       
		pkt_len = (uint16_t) (rte_le_to_cpu_16(rxd.wb.upper.length) -
				      rxq->crc_len);
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rte_packet_prefetch((char *)rxm->buf_addr + rxm->data_off);
		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;

		pkt_info = rte_le_to_cpu_32(rxd.wb.lower.lo_dword.data);
		/* Only valid if PKT_RX_VLAN set in pkt_flags */
		rxm->vlan_tci = rte_le_to_cpu_16(rxd.wb.upper.vlan);

		pkt_flags = rx_desc_status_to_pkt_flags(staterr, vlan_flags);
		pkt_flags = pkt_flags | rx_desc_error_to_pkt_flags(staterr);
		pkt_flags = pkt_flags |
			ixgbe_rxd_pkt_info_to_pkt_flags((uint16_t)pkt_info);
		rxm->ol_flags = pkt_flags;
		rxm->packet_type =
			ixgbe_rxd_pkt_info_to_pkt_type(pkt_info,
						       rxq->pkt_type_mask);

		if (likely(pkt_flags & PKT_RX_RSS_HASH))
			rxm->hash.rss = rte_le_to_cpu_32(
						rxd.wb.lower.hi_dword.rss);
		else if (pkt_flags & PKT_RX_FDIR) {
			rxm->hash.fdir.hash = rte_le_to_cpu_16(
					rxd.wb.lower.hi_dword.csum_ip.csum) &
					IXGBE_ATR_HASH_MASK;
			rxm->hash.fdir.id = rte_le_to_cpu_16(
					rxd.wb.lower.hi_dword.csum_ip.ip_id);
		}
		/*
		 * Store the mbuf address into the next entry of the array
		 * of returned packets.
		 */
		rx_pkts[nb_rx++] = rxm;
    }
    // 省略
}
```


1. 首先，取值`rx_id = rxq->rx_tail`,这个值初始化时为0，用来标识当前ring的尾。然后循环读取请求数量的描述符，这时候第一步判断就是这个描述符是否可用

2. 如果描述符的DD位不为1，则表明这个描述符网卡还没有准备好，也就是没有包。没有包，就跳出循环。

3. 如果描述符准备好了，就取出对应的描述符，因为网卡已经把一些信息存到了描述符里，可以后面把这些信息填充到新分配的数据包里。

下面阐述描述符准备好的情况: 一个狸猫换太子(sw_ring中的数据包地址交给mbuf)的过程

1. 先从mempool的ring中分配一个新的“狸猫”—mbuf

```c
nmb = rte_mbuf_raw_alloc(rxq->mb_pool);

```

2. 然后找到当前描述符对应的“太子”—ixgbe_rx_entry *rxe

```c
rxe = &sw_ring[rx_id];

```

3. 中间略掉关于预取的操作代码，之后，就要用这个狸猫换个太子

rxm的用户的mbuf的地址，需要将其对应到驱动的mbuf地址。

```c
rxm = rxe->mbuf;
rxe->mbuf = nmb;
```

下面是实际置换:这样换出来的太子rxm就是我们要取出来的数据包指针，在下面填充一些必要的信息，就可以把包返给接收的用户了

```c
pkt_len = (uint16_t) (rte_le_to_cpu_16(rxd.wb.upper.length) -
                rxq->crc_len);
rxm->data_off = RTE_PKTMBUF_HEADROOM;
rte_packet_prefetch((char *)rxm->buf_addr + rxm->data_off);
rxm->nb_segs = 1;
rxm->next = NULL;
rxm->pkt_len = pkt_len;
rxm->data_len = pkt_len;
rxm->port = rxq->port_id;

pkt_info = rte_le_to_cpu_32(rxd.wb.lower.lo_dword.data);
/* Only valid if PKT_RX_VLAN set in pkt_flags */
rxm->vlan_tci = rte_le_to_cpu_16(rxd.wb.upper.vlan);

pkt_flags = rx_desc_status_to_pkt_flags(staterr, vlan_flags);
pkt_flags = pkt_flags | rx_desc_error_to_pkt_flags(staterr);
pkt_flags = pkt_flags |
    ixgbe_rxd_pkt_info_to_pkt_flags((uint16_t)pkt_info);
rxm->ol_flags = pkt_flags;
rxm->packet_type =
    ixgbe_rxd_pkt_info_to_pkt_type(pkt_info,
                        rxq->pkt_type_mask);

if (likely(pkt_flags & PKT_RX_RSS_HASH))
    rxm->hash.rss = rte_le_to_cpu_32(
                rxd.wb.lower.hi_dword.rss);
else if (pkt_flags & PKT_RX_FDIR) {
    rxm->hash.fdir.hash = rte_le_to_cpu_16(
            rxd.wb.lower.hi_dword.csum_ip.csum) &
            IXGBE_ATR_HASH_MASK;
    rxm->hash.fdir.id = rte_le_to_cpu_16(
            rxd.wb.lower.hi_dword.csum_ip.ip_id);
}
/*
    * Store the mbuf address into the next entry of the array
    * of returned packets.
    */
rx_pkts[nb_rx++] = rxm;
```

注意最后一句话，就是把包的指针返回给用户。

其实在换太子中间过程中，还有一件非常重要的事要做，就是开头说的，在驱动读取完数据包后，要把描述符的DD标志位置为0，同时设置新的DMA地址指向新的mbuf空间，这么描述符就可以再次被网卡硬件使用，拷贝数据到mbuf空间了。

```c
dma_addr = rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(nmb));
rxdp->read.hdr_addr = 0;
rxdp->read.pkt_addr = dma_addr;

```

其中`rxdp->read.hdr_addr = 0;`这一个语句，就包含了设置DD位为0。
最后，就是检查空余可用描述符数量是否小于阀值，如果小于阀值，进行处理。不详细说了。

这样过后，收取数据包就完成了。

## 7.发包过程

在说发送之前，先说一下描述符的回写（write-back），回写是指把用过后的描述符，恢复其重新使用的过程。在接收数据包过程中，回写是立马执行的，也就是DMA使用描述符标识包可读取，然后驱动程序读取数据包，读取之后，就会把DD位置0，同时进行回写操作，这个描述符也就可以再次被网卡硬件使用了。

但是发送过程中，回写却不是立刻完成的。发送有两种方式进行回写：

1. Updating by writing back into the Tx descriptor
2. Update by writing to the head pointer in system memory

第二种回写方式貌似针对的网卡比较老，对于82599，使用第一种回写方式。在下面三种情况下，才能进行回写操作：

   - 1.TXDCTL[n].WTHRESH = 0 and a descriptor that has RS set is ready to be written back.
   - 2.TXDCTL[n].WTHRESH > 0 and TXDCTL[n].WTHRESH descriptors have accumulated.
   - 3.TXDCTL[n].WTHRESH > 0 and the corresponding EITR counter has reached zero. The timer expiration flushes any accumulated descriptors and sets an interrupt event(TXDW).

而在代码中，发送队列的初始化的时候，`ixgbe_dev_tx_queue_setup()`中

```c
txq->pthresh = tx_conf->tx_thresh.pthresh;
txq->hthresh = tx_conf->tx_thresh.hthresh;
txq->wthresh = tx_conf->tx_thresh.wthresh;
```

pthresh,hthresh,wthresh的值，都是从`tx_conf`中配置的值，而`tx_conf`如果在应用程序中没有赋值的话，就是采用的默认值：

```c
dev_info->default_txconf = (struct rte_eth_txconf) {
    .tx_thresh = {
        .pthresh = IXGBE_DEFAULT_TX_PTHRESH,
        .hthresh = IXGBE_DEFAULT_TX_HTHRESH,
        .wthresh = IXGBE_DEFAULT_TX_WTHRESH,
    },
    .tx_free_thresh = IXGBE_DEFAULT_TX_FREE_THRESH,
    .tx_rs_thresh = IXGBE_DEFAULT_TX_RSBIT_THRESH,
    .txq_flags = ETH_TXQ_FLAGS_NOMULTSEGS |
            ETH_TXQ_FLAGS_NOOFFLOADS,
};
```

其中的wthresh就是0，其余两个是32.也就是说这种设置下，回写取决于RS标志位。RS标志位主要就是为了标识已经积累了一定数量的描述符，要进行回写了。

了解了这个，就来看看代码吧，从`ixgbe_xmit_pkts()`开始，为了看主要的框架，忽略掉网卡卸载等相关的功能的代码，主要看发送和回写的实现:

1. 先检查剩余的描述符是否已经小于阈值，如果小于阈值，那么就先清理回收一下描述符

```c
if (txq->nb_tx_free < txq->tx_free_thresh)
        ixgbe_xmit_cleanup(txq);
```

### 7.1清理回收发送描述符流程详解

这是一个重要的操作，进去看看是怎么清理回收的：`ixgbe_xmit_cleanup(txq)`

```c
/* Reset transmit descriptors after they have been used */
static inline int
ixgbe_xmit_cleanup(struct ixgbe_tx_queue *txq)
{
	struct ixgbe_tx_entry *sw_ring = txq->sw_ring;
	volatile union ixgbe_adv_tx_desc *txr = txq->tx_ring;
	uint16_t last_desc_cleaned = txq->last_desc_cleaned;
	uint16_t nb_tx_desc = txq->nb_tx_desc;
	uint16_t desc_to_clean_to;
	uint16_t nb_tx_to_clean;
	uint32_t status;
    // 取出上次清理的描述符位置，很明显，这次清理就接着上次的位置开始。
    // 根据上次的位置，加上txq->tx_rs_thresh个描述符，就是标记有RS的描述符的位置
    // tx_rs_thresh就是表示这么多个描述符后，设置RS位，进行回写。
    // 所以，从上次清理的位置跳过tx_rs_thresh个描述符，就能找到标记有RS的位置
	/* Determine the last descriptor needing to be cleaned  */
	desc_to_clean_to = (uint16_t)(last_desc_cleaned + txq->tx_rs_thresh);
	if (desc_to_clean_to >= nb_tx_desc)
		desc_to_clean_to = (uint16_t)(desc_to_clean_to - nb_tx_desc);
    
	/* Check to make sure the last descriptor to clean is done */
	desc_to_clean_to = sw_ring[desc_to_clean_to].last_id;
	status = txr[desc_to_clean_to].wb.status;
    // 检查标记RS位置的描述符DD位，如果已经设置为1，则可以进行清理回收，否则，就不能清理。
	if (!(status & rte_cpu_to_le_32(IXGBE_TXD_STAT_DD))) {
		PMD_TX_FREE_LOG(DEBUG,
				"TX descriptor %4u is not done"
				"(port=%d queue=%d)",
				desc_to_clean_to,
				txq->port_id, txq->queue_id);
		/* Failed to clean any descriptors, better luck next time */
		return -(1);
	}
    // 确认要清理的描述符个数
	/* Figure out how many descriptors will be cleaned */
	if (last_desc_cleaned > desc_to_clean_to)
		nb_tx_to_clean = (uint16_t)((nb_tx_desc - last_desc_cleaned) +
							desc_to_clean_to);
	else
		nb_tx_to_clean = (uint16_t)(desc_to_clean_to -
						last_desc_cleaned);

	PMD_TX_FREE_LOG(DEBUG,
			"Cleaning %4u TX descriptors: %4u to %4u "
			"(port=%d queue=%d)",
			nb_tx_to_clean, last_desc_cleaned, desc_to_clean_to,
			txq->port_id, txq->queue_id);

	/*
	 * The last descriptor to clean is done, so that means all the
	 * descriptors from the last descriptor that was cleaned
	 * up to the last descriptor with the RS bit set
	 * are done. Only reset the threshold descriptor.
	 */
     // 把标记有RS位的描述符中的RS位清掉，确切的说，DD位等都清空了。调整上次清理的位置和空闲描述符大小
	txr[desc_to_clean_to].wb.status = 0;

	/* Update the txq to reflect the last descriptor that was cleaned */
	txq->last_desc_cleaned = desc_to_clean_to;
	txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + nb_tx_to_clean);

	/* No Error */
	return 0;
}
```

1. 取出上次清理的描述符位置，很明显，这次清理就接着上次的位置开始。

这里说明下怎么获取到RS描述符的: 根据上次的位置，加上`txq->tx_rs_thresh`个描述符，就是标记有RS的描述符的位置，因为`tx_rs_thresh`就是表示这么多个描述符后，设置RS位，进行回写。所以，从上次清理的位置跳过`tx_rs_thresh`个描述符，就能找到标记有RS的位置。

```c
desc_to_clean_to = (uint16_t)(last_desc_cleaned + txq->tx_rs_thresh);
```

2. 当网卡把队列的数据包发送完成后，就会把DD位设置为1，这个时候，先检查标记RS位置的描述符DD位，如果已经设置为1，则可以进行清理回收，否则，就不能清理。`if (!(status & rte_cpu_to_le_32(IXGBE_TXD_STAT_DD)))`
3. 接下来确认要清理的描述符个数
```c
if (last_desc_cleaned > desc_to_clean_to)
    nb_tx_to_clean = (uint16_t)((nb_tx_desc - last_desc_cleaned) +
                        desc_to_clean_to);
else
    nb_tx_to_clean = (uint16_t)(desc_to_clean_to -
                    last_desc_cleaned);
```

3. 最后把标记有RS位的描述符中的RS位清掉，确切的说，DD位等都清空了。调整上次清理的位置和空闲描述符大小。

```c
txr[desc_to_clean_to].wb.status = 0;

/* Update the txq to reflect the last descriptor that was cleaned */
txq->last_desc_cleaned = desc_to_clean_to;
txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + nb_tx_to_clean);
```

这样，就算清理完毕了。

接着继续看发送，依次处理每个要发送的数据包：
取出数据包，取出其中的卸载标志
ol_flags = tx_pkt->ol_flags;

/* If hardware offload required */
tx_ol_req = ol_flags & IXGBE_TX_OFFLOAD_MASK;
if (tx_ol_req) {
    tx_offload.l2_len = tx_pkt->l2_len;
    tx_offload.l3_len = tx_pkt->l3_len;
    tx_offload.l4_len = tx_pkt->l4_len;
    tx_offload.vlan_tci = tx_pkt->vlan_tci;
    tx_offload.tso_segsz = tx_pkt->tso_segsz;
    tx_offload.outer_l2_len = tx_pkt->outer_l2_len;
    tx_offload.outer_l3_len = tx_pkt->outer_l3_len;

    /* If new context need be built or reuse the exist ctx. */
    ctx = what_advctx_update(txq, tx_ol_req,
        tx_offload);
    /* Only allocate context descriptor if required*/
    new_ctx = (ctx == IXGBE_CTX_NUM);
    ctx = txq->ctx_curr;
}
这里卸载还要使用一个描述符，暂时不明白。
计算了发送这个包需要的描述符数量，主要是有些大包会分成几个segment,每个segment
nb_used = (uint16_t)(tx_pkt->nb_segs + new_ctx);
如果这次要用的数量加上设置RS之后积累的数量，又到达了tx_rs_thresh，那么就设置RS标志。
if (txp != NULL &&
        nb_used + txq->nb_tx_used >= txq->tx_rs_thresh)
/* set RS on the previous packet in the burst */
txp->read.cmd_type_len |=
    rte_cpu_to_le_32(IXGBE_TXD_CMD_RS);
接下来要确保用足够可用的描述符
如果描述符不够用了，就先进行清理回收，如果没能清理出空间，则把最后一个打上RS标志，更新队列尾寄存器，返回已经发送的数量。
if (txp != NULL)
        txp->read.cmd_type_len |= rte_cpu_to_le_32(IXGBE_TXD_CMD_RS);

    rte_wmb();

    /*
     * Set the Transmit Descriptor Tail (TDT)
     */
    PMD_TX_LOG(DEBUG, "port_id=%u queue_id=%u tx_tail=%u nb_tx=%u",
           (unsigned) txq->port_id, (unsigned) txq->queue_id,
           (unsigned) tx_id, (unsigned) nb_tx);
    IXGBE_PCI_REG_WRITE_RELAXED(txq->tdt_reg_addr, tx_id);
    txq->tx_tail = tx_id;
接下来的判断就很有意思了，
unlikely(nb_used > txq->tx_rs_thresh)
为什么说它奇怪呢？其实他自己都标明了unlikely,一个数据包会分为N多segment,多于txq->tx_rs_thresh（默认可是32啊），但即使出现了这种情况，也没做更多的处理，只是说会影响性能，然后开始清理描述符，其实这跟描述符还剩多少没有半毛钱关系，只是一个包占的描述符就超过了tx_rs_thresh,然而，并不见得是没有描述符了。所以，这时候清理描述符意义不明。
下面的处理应该都是已经有充足的描述符了，如果卸载有标志，就填充对应的值。不详细说了。
然后，就把数据包放到发送队列的sw_ring,并填充信息
m_seg = tx_pkt;
    do {
        txd = &txr[tx_id];
        txn = &sw_ring[txe->next_id];
        rte_prefetch0(&txn->mbuf->pool);

        if (txe->mbuf != NULL)
            rte_pktmbuf_free_seg(txe->mbuf);
        txe->mbuf = m_seg;

        /*
         * Set up Transmit Data Descriptor.
         */
        slen = m_seg->data_len;
        buf_dma_addr = rte_mbuf_data_dma_addr(m_seg);
        txd->read.buffer_addr =
            rte_cpu_to_le_64(buf_dma_addr);
        txd->read.cmd_type_len =
            rte_cpu_to_le_32(cmd_type_len | slen);
        txd->read.olinfo_status =
            rte_cpu_to_le_32(olinfo_status);
        txe->last_id = tx_last;
        tx_id = txe->next_id;
        txe = txn;
        m_seg = m_seg->next;
    } while (m_seg != NULL);
这里是把数据包的每个segment都放到队列sw_ring，很关键的是设置DMA地址，设置数据包长度和卸载参数。
一个数据包最后的segment的描述符需要一个EOP标志来结束。再更新剩余的描述符数：
cmd_type_len |= IXGBE_TXD_CMD_EOP;
txq->nb_tx_used = (uint16_t)(txq->nb_tx_used + nb_used);
txq->nb_tx_free = (uint16_t)(txq->nb_tx_free - nb_used);
然后再次检查是否已经达到了tx_rs_thresh，并做处理
if (txq->nb_tx_used >= txq->tx_rs_thresh) {
    PMD_TX_FREE_LOG(DEBUG,
            "Setting RS bit on TXD id="
            "%4u (port=%d queue=%d)",
            tx_last, txq->port_id, txq->queue_id);

    cmd_type_len |= IXGBE_TXD_CMD_RS;

    /* Update txq RS bit counters */
    txq->nb_tx_used = 0;
    txp = NULL;
} else
    txp = txd;

txd->read.cmd_type_len |= rte_cpu_to_le_32(cmd_type_len);
最后仍是做一下末尾的处理，更新队列尾指针。发送就结束啦！！
IXGBE_PCI_REG_WRITE_RELAXED(txq->tdt_reg_addr, tx_id);
txq->tx_tail = tx_id;

# 总结

可以看出数据包的发送和接收过程与驱动紧密相关，也与配置有关，尤其是对于收发队列的参数配置，将直接影响性能，可以根据实际进行调整。