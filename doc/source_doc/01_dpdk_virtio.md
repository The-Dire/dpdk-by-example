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


