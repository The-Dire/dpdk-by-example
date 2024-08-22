# dpdk初始化过程分析

dpdk核心是收发包都在用户态，因此其初始化过程中实际上进行了相应驱动的绑定。本文重点就在于网卡驱动怎么嵌入到dpdk给用户的runtime library中的。

注：本文的代码基于DPDK 19.08。

## 1. dpdk初始化的两大阶段

dpdk 程序初始化可以以 main 函数为界限划分为两个阶段，第一个阶段为 main 函数之前 dpdk 内部构造函数的执行，执行完成后会初始化几个重要的链表：如 tailq 链表与 dpdk 驱动链表。
第二个阶段为 main 函数中调用 rte_eal_init 来显示的初始化 dpdk 程序的 eal 环境，此函数代码很少，其背后隐藏的细节却非常多，本文中将从这两个阶段入手，描述 dpdk 程序初始化 eal 环境的主要原理。

## 2. dpdk初始化第一阶段

dpdk 支持多个网卡驱动，并且在不断扩展，dpdk 使用 gcc constructor 机制通过构造函数将网卡驱动注册到链表中，统一了驱动注册的框架，增加新的驱动时，只需要声明一个注册语句即可。

老版本的DPDK注册的链表是`dev_driver_list`。

较新的版本DPDK通过`rte_pci_bus`结构统一管理。

```c
struct rte_pci_bus {
	struct rte_bus bus;               /**< Inherit the generic class */
	struct rte_pci_device_list device_list;  /**< List of PCI devices */
	struct rte_pci_driver_list driver_list;  /**< List of PCI drivers */
};

```

网卡驱动注册到`rte_pci_bus`中的`driver_list`链表里的。具体参照`rte_pci_register`函数，DPDK大部分驱动都是通过宏`RTE_PMD_REGISTER_PCI`注册到DPDK的统一管理链表中的，而`RTE_PMD_REGISTER_PCI`宏就是调用了`rte_pci_register`函数。

在第一阶段 dpdk 还初始化了 `rte_tailq_elem_head` 这个 `tailq` 链表，初始化过程仅仅将不同模块中声明的 `tailq` 链起来，真正的初始化在 `rte_eal_tailqs_init` 中完成。

在一些模块中也有一些通过 constructor 声明的函数，不进一步描述。

dpdk 初始化过程相对复杂，这里只分析网卡接口初始化的流程。

## 3. 端口初始化

下图是dpdk 16.04的调用图，与新版本差别不大。

![](resource/dpdk_eal_init.png)

