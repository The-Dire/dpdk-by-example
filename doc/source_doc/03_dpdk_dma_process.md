# dpdk 收发包DMA过程

本文简述dpdk收发包流程，和前两篇相比更加简单。基于dpdk 16.04版本。

简述：dpdk使用dma方式将收到的报文保存在事先分配好的mbuf里面，收发报文时零拷贝。具体是怎么实现零拷贝的呢。主要的就是配置网卡的收发队列描述符，设置网卡DMA拷贝数据包的目的地址为mbuf的物理地址，配置好地址后，网卡收到数据包后会通过DMA控制器直接把数据包拷贝到指定的内存地址。



# 1.配置网卡总的收发队列个数，分配好rx_queues,tx_queues指针数组

```c
rte_eth_dev_configure(port_id, nb_rx_q,nb_tx_q,*dev_conf);
dev->data->rx_queues = rte_zmalloc("ethdev->rx_queues", sizeof(dev->data->rx_queues[0]) * nb_queues,RTE_CACHE_LINE_SIZE);
dev->data->nb_rx_queues = nb_queues;
dev->data->tx_queues = rte_zmalloc("ethdev->tx_queues", sizeof(dev->data->tx_queues[0]) * nb_queues,RTE_CACHE_LINE_SIZE);
dev->data->nb_tx_queues = nb_queues;
```

# 2.配置每个队列，为每个队列创建队列描述符队列，sw_ring队列
```c
struct ixgbe_rx_queue {
struct rte_mempool  *mb_pool; /**< mbuf pool to populate RX ring. */
volatile union ixgbe_adv_rx_desc *rx_ring; /**< RX ring virtual address. */
uint64_t            rx_ring_phys_addr; /**< RX ring DMA address. */
volatile uint32_t   *rdt_reg_addr; /**< RDT register address. */
volatile uint32_t   *rdh_reg_addr; /**< RDH register address. */
struct ixgbe_rx_entry *sw_ring; /**< address of RX software ring. */
uint16_t            nb_rx_desc; /**< number of RX descriptors. */
uint16_t            rx_tail;  /**< current value of RDT register. */
uint16_t            nb_rx_hold; /**< number of held free RX desc. */
uint16_t            rx_free_thresh; /**< max free RX desc to hold. */
uint16_t            queue_id; /**< RX queue index. */
uint8_t             port_id;  /**< Device port identifier. */
///省略
};
```

`rte_eth_rx_queue_setup(port_id, queue_id,nb_rx_desc, socket_id,*rx_conf,rte_mempool *mp)`该函数会调用到驱动的rx_queue_setup，以ixgbe为例为ixgbe_dev_rx_queue_setup。
## 2.1 创建队列结构体，并填充结构
`rxq = rte_zmalloc_socket("ethdev RX queue", sizeof(struct ixgbe_rx_queue),RTE_CACHE_LINE_SIZE, socket_id);`
填充结构体的所属内存池，描述符个数，队列号，队列所属接口号等成员。
## 2.2创建描述符队列，队列大小为的描述符个数
`rz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx, RX_RING_SZ, IXGBE_ALIGN, socket_id);`
设置队列的接收描述符ring的物理地址及虚拟地址：

```c
rxq->rx_ring_phys_addr = rte_mem_phy2mch(rz->memseg_id, rz->phys_addr);
rxq->rx_ring = (union ixgbe_adv_rx_desc *) rz->addr;
```

读取出 队列对应的头和尾寄存器的地址：

```c
rxq->rdt_reg_addr =  IXGBE_PCI_REG_ADDR(hw, IXGBE_RDT(rxq->reg_idx));
rxq->rdh_reg_addr =  IXGBE_PCI_REG_ADDR(hw, IXGBE_RDH(rxq->reg_idx));
```

## 2.3分配sw_ring，这个ring中存储的对象是mbuf的指针。
```c
rxq->sw_ring = rte_zmalloc_socket("rxq->sw_ring",
        sizeof(struct ixgbe_rx_entry) * len,RTE_CACHE_LINE_SIZE, socket_id);
```
ixgbe_rx_entry里面就是mbuf指针
 
## 2.4让`dev->data->rx_queues[queue_idx]`指向2.1创建的ixgbe_rx_queue对象;

```c
dev->data->rx_queues[queue_idx] = rxq;
```
 
## 2.5初始化队列变量，把分配的描述符队列清空

```c
for (i = 0; i < len; i++) {
    rxq->rx_ring[i] = zeroed_desc;
}
rxq->rx_nb_avail = 0;
rxq->rx_next_avail = 0;
rxq->rx_free_trigger = (uint16_t)(rxq->rx_free_thresh – 1);
rxq->rx_tail = 0;
rxq->nb_rx_hold = 0;
rxq->pkt_first_seg = NULL;
rxq->pkt_last_seg = NULL;
```

这样，接收队列就初始化完了。

## 2.6对于发送队列，1,2,3,4等步骤都与接收队列一样的逻辑，但初始化时赋值如下：
```c
txq->tx_rs_thresh = tx_rs_thresh;
txq->tx_free_thresh = tx_free_thresh;
txq->tdt_reg_addr = IXGBE_PCI_REG_ADDR(hw, IXGBE_TDT(txq->reg_idx));
txq->tx_tail = 0;
txq->nb_tx_used = 0;
txq->last_desc_cleaned = (uint16_t)(txq->nb_tx_desc – 1);
txq->nb_tx_free = (uint16_t)(txq->nb_tx_desc – 1);
```
最后让sw_ring构成一个链表，每个entry的neixid指向下一个entry的id，mbuf为NULL。每个描述符的dd位置一。
```c
prev = (uint16_t) (txq->nb_tx_desc – 1);
for (i = 0; i < txq->nb_tx_desc; i++) {
    volatile union ixgbe_adv_tx_desc *txd = &txq->tx_ring[i];
    txd->wb.status = rte_cpu_to_le_32(IXGBE_TXD_STAT_DD);
    txe[i].mbuf = NULL;
    txe[i].last_id = i;
    txe[prev].next_id = i;
    prev = i;
}
```
# 3.为收包队列分配mbuf，并将物理地址及虚拟地址分别赋值给队列描述符及sw_ring.

经过上面的队列初始化，队列的描述符ring和sw_ring都分配了，但DMA仍然还不知道要把数据包拷贝到哪里.接下来就是建立mempool,queue,DMA,描述符ring,sw_ring之间的关系.这些动作是在rte_eth_dev_start()–》ixgbe_dev_start()里面实现的
 
## 3.1把rx,tx描述符ring的物理地址及长度写入了网卡寄存器，还初始化化了RDT,RDH,TDT,TDH寄存器
举例：`ixgbe_dev_rx_init()`

```c
for (i = 0; i < dev->data->nb_rx_queues; i++) {
    rxq = dev->data->rx_queues[i];
    bus_addr = rxq->rx_ring_phys_addr;
    IXGBE_WRITE_REG(hw, IXGBE_RDBAL(rxq->reg_idx),
    (uint32_t)(bus_addr & 0x00000000ffffffffULL));
    IXGBE_WRITE_REG(hw, IXGBE_RDBAH(rxq->reg_idx),
    (uint32_t)(bus_addr >> 32));
    IXGBE_WRITE_REG(hw, IXGBE_RDLEN(rxq->reg_idx),
    rxq->nb_rx_desc * sizeof(union ixgbe_adv_rx_desc));
    IXGBE_WRITE_REG(hw, IXGBE_RDH(rxq->reg_idx), 0);
    IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx), 0);
}
```
ixgbe_dev_tx_init()把tx描述符ring的物理地址及长度写入了寄存器，还初始化化了TDT,TDH寄存器

## 3.2对于收队列，从队列所属内存池的ring中循环取出了nb_rx_desc个mbuf指针，依次将每个mbuf的虚拟地址及物理地址放入队列的sw_ring，描述符 ring。
ixgbe_dev_rxtx_start():

```c
for (i = 0; i < dev->data->nb_rx_queues; i++) {
    ret = ixgbe_dev_rx_queue_start(dev, i);
}
for (i = 0; i < dev->data->nb_tx_queues; i++) {
    ret = ixgbe_dev_tx_queue_start(dev, i);
} 
```

ixgbe_dev_rx_queue_start–>ixgbe_alloc_rx_queue_mbufs函数完成了mempool、ring、queue ring、queue sw_ring的关系建立！

```c
ixgbe_alloc_rx_queue_mbufs(struct ixgbe_rx_queue *rxq)
{
    struct ixgbe_rx_entry *rxe = rxq->sw_ring;
    uint64_t dma_addr;
    unsigned i;
    /* Initialize software ring entries */
    for (i = 0; i < rxq->nb_rx_desc; i++) {
        volatile union ixgbe_adv_rx_desc *rxd;
        struct rte_mbuf *mbuf = rte_rxmbuf_alloc(rxq->mb_pool);
        // 省略
        dma_addr =rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(mbuf));
        rxd = &rxq->rx_ring[i];
        rxd->read.hdr_addr = 0;
        rxd->read.pkt_addr = dma_addr;
        rxe[i].mbuf = mbuf;
    }
    return 0;
}
```
## 3.3使能DMA hw->mac.ops.enable_rx_dma(hw, rxctrl);
 
## 3.4最后再设置一下队列ring的头尾寄存器的值，这也是很重要的一点！头设置为0，尾设置为描述符个数减1，就是描述符填满整个ring。

```c
IXGBE_WRITE_REG(hw, IXGBE_RDH(rxq->reg_idx), 0);
IXGBE_WRITE_REG(hw, IXGBE_RDT(rxq->reg_idx), rxq->nb_rx_desc – 1);
 
ixgbe_dev_tx_queue_start发报队列启动
IXGBE_WRITE_REG(hw, IXGBE_TDH(txq->reg_idx), 0);
IXGBE_WRITE_REG(hw, IXGBE_TDT(txq->reg_idx), 0);
```
发送队列的启动比接收队列的启动要简单，只是配置了txdctl寄存器，延时等待TX使能完成，最后，设置队列的头和尾位置都为0

# 4.收发队列配置总结：

每个收队列：
   收队列分配了nb_rx_desc个sw_ring，每个sw_ring里面都存储了从mempool里面分配的一个mbuf的虚拟地址，对应的物理地址存储在了描述符rx_ring里面。
   分配了nb_rx_desc个描述符rx_ring，每个描述符里：存储标记位，rss值，vlan头及mbuf的物理地址等。rx_ring的物理地址及个数写入了网卡的寄存器。RDH RDT寄存器存储rx_ring的队尾对头index，初始RDH为0，RDT为nb_rx_desc-1.表示队列为空，还没收到一个报文。
每个发队列：
   分配了nb_tx_desc个sw_ring，每个sw_ring里面是一个mbu指针，初始没有分配mbuf。待发送报文时赋值
   分配了nb_tx_desc个描述符tx_ring，每个描述符里面可存储bufaddr及dd标记，初初始bufadd为NULL，dd为 1。rx_ring的物理地址及个数写入了网卡的寄存器。TDH TDT寄存器存储描述符的头尾,初始都为0。


# 5.收报文
队列数据包的获取`rte_eth_rx_burst()–>ixgbe_recv_pkts`

## 5.1首先，取值当前描述符对尾：
   rx_id = rxq->rx_tail,这个值初始化时为0。


## 5.2循环读取请求数量的描述符rx_ring，步判断就是这个描述符是否可用
```c
while (nb_rx < nb_pkts) {
    rxdp = &rxq->rx_ring[rx_id];
    staterr = rxdp->wb.upper.status_error;
    if (!(staterr & rte_cpu_to_le_32(IXGBE_RXDADV_STAT_DD)))
        break;
    ……
}
```
如果描述符的DD位不为1，则表明这个描述符网卡还没有准备好，也就是没有包，就跳出循环。
如果描述符准备好了，就取出对应的描述符.

## 5.3置换出填充了报文的mbuf

先从mempool的ring中分配一个新的“狸猫”—mbuf
```c
newmbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
dma_addr = rte_cpu_to_le_64(rte_mbuf_data_dma_addr_default(newmbuf));
```
  然后找到当前描述符对应的“太子”—`ixgbe_rx_entry *rxe`

```c
rxe = &sw_ring[rx_id];
rx_id++;
```
之后，就要用这个狸猫换个太子

```c
rxm =  rxe->mbuf; 太子rxm
rxe->mbuf = newmbuf;  //新的mbuf虚拟地址赋值给sw_ring[rx_id]
rxdp->read.pkt_addr = dma_addr;//新的mbuf物理地址赋值给描述符   
    rxdp->read.hdr_addr = 0;  //描述符x_ring[rx_id]的dd位置0
rxm->pkt_len = pkt_len; //rxm填充一些必要的信息
    …..
    rx_pkts[nb_rx++] = rxm; //返回给收报用户
}//while循环结束
```
## 5.4最后从新赋值rx_tail及rdt寄存器

```c
    rxq->rx_tail = rx_id;
    nb_hold = (uint16_t) (nb_hold + rxq->nb_rx_hold);
    if (nb_hold > rxq->rx_free_thresh) {
        rx_id = (uint16_t) ((rx_id == 0) ?  (rxq->nb_rx_desc – 1) : (rx_id – 1));
        IXGBE_PCI_REG_WRITE(rxq->rdt_reg_addr, rx_id);
        nb_hold = 0;
    }
    rxq->nb_rx_hold = nb_hold;
```

## 5.5总结收报： 

网卡DMA收到报文，从RDH指向的描述符位置(dd标记位为0，表示该描述符可用）开始，将报文写入描述符里面的pkt_addr地址，实际就是mbuf物理地址,并将描述符dd为置1(表示该位置已经写入了报文)，直到没有报文了或RDH到达了RDT的位置，表示队列满了，要等到业务收了包才能继续放入。

业务调用rte_eth_rx_burst收报文，从RDH描述符位置开始(初始为0)，判断dd标记位为1，表示有报文，从mempool里面分配一个mbuf置换当前描述符对应的mbuf，老的mbuf地址存储到rx_pkts[]里面。该描述符项dd置0。每收一个报文，rx_tail++.最后收完报文，将RDT寄存器的值赋值为rx_tail减一。


# 6.发报文

队列数据包的发送rte_eth_tx_burst()–>ixgbe_xmit_pkts。发包时一个报文可能有多个mbuf，要占用多个描述符位置

## 6.1首先，取值当前描述符对尾：
   tx_id = txq->tx_tail,这个值初始化时为0。
## 6.2循环读取每个要发送的数据包，做一些判断
1. 计算发送这个包需要的描述符数量，有些大包会分成几个segment
```c
    nb_used = (uint16_t)(tx_pkt->nb_segs + new_ctx);
        tx_last = (uint16_t) (tx_id + nb_used – 1);
```
2. 如果这次要用的数量加上之前积累的数量到达了tx_rs_thresh，那么就设置RS标志。txp为上次  发送报文使用的最后一个描述符。描述符设置了RS位，网卡轮询时就会把那一段的报文发送。
```c
   if (txp != NULL && nb_used + txq->nb_tx_used >= txq->tx_rs_thresh)
        txp->read.cmd_type_len |= rte_cpu_to_le_32(IXGBE_TXD_CMD_RS);
```
3. 如果tx_free不够用于发送报文，检测部分已经发送了的报文，更新nb_rx_free
```c 
    if (nb_used > txq->nb_tx_free) ixgbe_xmit_cleanup(txq)
```

## 6.3发送报文
1. 遍历每个报文的m_seg，从tx_id描述符开始，赋值每个描述符的buffer_addr为m_seg的物理地址,并释放sw_ring里面对应的老的mbuf，赋值为新的m_seg虚拟地址。
```c
txe = &sw_ring[tx_id];
m_seg = tx_pkt;
do {
//释放sw_ring里面老的mbuf地址，赋值为新的m_seg地址，并赋值报文最后一个段的id
if (txe->mbuf != NULL)
rte_pktmbuf_free_seg(txe->mbuf);
txe->mbuf = m_seg;
        txe->last_id = tx_last;
       //赋值tx_ring描述符为待发送m_seg的物理地址
buf_dma_addr = rte_mbuf_data_dma_addr(m_seg);
        txd = &txq->tx_ring[rx_id];
txd->read.buffer_addr =rte_cpu_to_le_64(buf_dma_addr);
        //调到下一个sw_ring,tx_ring,m_seg
        txe =&sw_ring[txe->next_id];
tx_id = txe->next_id;
m_seg = m_seg->next;
} while (m_seg != NULL);
```

2. 之后累加nb_tx_used，累减nb_tx_free
```c
txq->nb_tx_used = (uint16_t)(txq->nb_tx_used + nb_used);
txq->nb_tx_free = (uint16_t)(txq->nb_tx_free – nb_used);
```
3. 最后判断已经填充的描述符数大于rs_thresh,设置描述符的rs标记位位1，重新计数
```c
if (txq->nb_tx_used >= txq->tx_rs_thresh) {
    cmd_type_len |= IXGBE_TXD_CMD_RS;
    txq->nb_tx_used = 0;
    txp = NULL;
} else
    txp = txd;
txd->read.cmd_type_len |= rte_cpu_to_le_32(cmd_type_len);
```
4. 最后从新赋值tx_tail及tdt寄存器为tx_id
```c
    IXGBE_PCI_REG_WRITE(txq->tdt_reg_addr, tx_id);
    txq->tx_tail = tx_id;
```

## 6.4总结发包：

业务调用rte_eth_tx_burst收报时，判断空闲描述符数足够的话，从tx_queues[i]->tx_tail描述符位置开始(初始为0)，将待发送报文的每个mseg的物理地址及虚拟地址依次赋值给描述符的buffer_addr及sw_ring的mbuf指针。如果待填充的sw_ring位置有老的mbuf存在，释放。最后更新tx_tail及TDT寄存器的值为新的tx_tail。

网卡检测到有可发送的报文时(TDH!=TDT),发送报文后，检测到描述符的rs标记位，将dd置1，表示报文已经发送（不释放mbuf）。更新TDH寄存器值。

ixgbe_xmit_cleanup详细分析：

```c
//清理其实不是真的清理描述符队列，只是判断待发送的mbuf是否已经被网卡发送，更新nb_tx_free的值。
ixgbe_xmit_cleanup(struct ixgbe_tx_queue *txq)
{
    volatile union ixgbe_adv_tx_desc *txr = txq->tx_ring;
    uint16_t last_desc_cleaned = txq->last_desc_cleaned;
    //desc_to_clean_to的描述符位置计算：上次清理到的位置+tx_rs_thresh，
    //并再往后移位到这报文最后一个mbuf的位置（报文有多高mbuf段的情况）。
    desc_to_clean_to = (uint16_t)(last_desc_cleaned + txq->tx_rs_thresh);
    if (desc_to_clean_to >= nb_tx_desc)
        desc_to_clean_to = (uint16_t)(desc_to_clean_to – nb_tx_desc);
        desc_to_clean_to = sw_ring[desc_to_clean_to].last_id;
        //当网卡把队列的数据包发送完成后，就会把DD位设置为1
        //先检查desc_to_clean_to位置的描述符DD位为1，则可以进行清理回收
        status = txr[desc_to_clean_to].wb.status;
    if (!(status & rte_cpu_to_le_32(IXGBE_TXD_STAT_DD)))
    {
        return -(1);
    }
 
    //计算清理的个数
    if (last_desc_cleaned > desc_to_clean_to)
        nb_tx_to_clean = (uint16_t)((nb_tx_desc – last_desc_cleaned) +desc_to_clean_to);
    else
        nb_tx_to_clean = (uint16_t)(desc_to_clean_to – last_desc_cleaned);
    
        //开始清理，dd为置0，last_desc_cleaned赋值为desc_to_clean_to
        txr[desc_to_clean_to].wb.status = 0;
        txq->last_desc_cleaned = desc_to_clean_to;
        txq->nb_tx_free = (uint16_t)(txq->nb_tx_free + nb_tx_to_clean);
        return 0;
}
```