# dpdk用户态驱动总线框架浅析

dpdk的老版本是没有总线框架的，在之前的 [1.dpdk初始化实现分析](doc/source_doc/01_dpdk_init.md) 中提到过。

老版本的DPDK注册的链表是`dev_driver_list`。

较新的版本DPDK通过`rte_pci_bus`结构统一管理。而dpdk有非常多种类的总线，dpdk新版本还存在`rte_dpaa_bus`,实际上dpdk引入了`rte_bus` 抽象模型，这个模型类似于内核的总线模型。

老版本中没有总线的概念，本该由总线提供的功能在 `rte_eal_init` 函数执行逻辑中隐藏。当引入了总线抽象后，设备的枚举、设备驱动的 probe 等过程都合并到总线中，驱动框架变得更加复杂，层次却更分明了。

下面的分析基于 dpdk 较新的代码探讨下 dpdk `rte_bus` 框架的部分实现细节。

## dpdk rte_bus 抽象结构

rte_bus 作为一种抽象数据结构，可以被实例化为多种不同的类型，如 pci 总线、vdev 总线、dpaa 总线等等。dpdk 中使用了一个链表来将多种总线类型实例链接起来，通过这一链表实现总线的注册、删除、并封装对每个已注册总线虚函数（scan、probe）的调用。

rte_bus 抽象类定义如下：

```c
struct rte_bus {
    RTE_TAILQ_ENTRY(rte_bus) next; /**< Next bus object in linked list */
    const char *name;            /**< Name of the bus */
    rte_bus_scan_t scan;         /**< Scan for devices attached to bus */
    rte_bus_probe_t probe;       /**< Probe devices on bus */
    rte_bus_find_device_t find_device; /**< Find a device on the bus */
    rte_bus_plug_t plug;         /**< Probe single device for drivers */
    rte_bus_unplug_t unplug;     /**< Remove single device from driver */
    rte_bus_parse_t parse;       /**< Parse a device name */
    rte_bus_devargs_parse_t devargs_parse; /**< Parse bus devargs */
    rte_dev_dma_map_t dma_map;   /**< DMA map for device in the bus */
    rte_dev_dma_unmap_t dma_unmap; /**< DMA unmap for device in the bus */
    struct rte_bus_conf conf;    /**< Bus configuration */
    rte_bus_get_iommu_class_t get_iommu_class; /**< Get iommu class */
    rte_dev_iterate_t dev_iterate; /**< Device iterator. */
    rte_bus_hot_unplug_handler_t hot_unplug_handler;
                /**< handle hot-unplug failure on the bus */
    rte_bus_sigbus_handler_t sigbus_handler;
                    /**< handle sigbus error on the bus */
};
```

多个总线之间通过链表链接起来，一个总线使用字符串表示的名称唯一标识。`rte_bus` 方法可以分为如下几个类型：

1. 设备枚举与驱动 probe 方法
2. 设备查找方法
3. 总线配置相关方法
4. 设备 dma 映射相关方法
5. 设备热插拔相关方法

eal_common_bus.c 中封装了总线链表的方法与调用总线方法的 api 接口。总线链表提供的外部 api 有如下内容：

1. 注册一个 rte_bus 总线实例到总线链表中
2. 从总线链表中移除一个 rte_bus 代表的总线实例
3. 依次调用总线链表中每一个 rte_bus 总线的 scan 方法来枚举设备
4. 依次调用总线链表中每一个 rte_bus 总线的 probe 方法来初始化挂到相应总线上的设备
5. 依次 dump 总线链表中每一个 rte_bus 总线的信息
6. 根据用户配置获取目标总线的 rte_bus 结构
7. 查找某个设备挂入总线的 rte_bus 结构
8. 获取支持所有总线的 iommu 映射类型
   
    
dpdk 封装了如下宏定义来注册一个总线：

```c
#define RTE_REGISTER_BUS(nm, bus) \
RTE_INIT_PRIO(businitfn_ ##nm, BUS) \
{\
    (bus).name = RTE_STR(nm);\
    rte_bus_register(&bus); \
}
```

此宏通过 gcc constructor 扩展功能注册总线，使用 RTE_INIT_PRIO 设定了总线注册的 constructor 优先级高于 PMD 驱动，确保驱动注册前总线已经注册完成。

rte_bus 结构提供如下 api 接口：

1. 获取总线名称
2. dump 总线信息
3. 查找目标总线
4. 查找总线上挂的某个设备
5. 调用总线注册的 sigbus 信号处理函数
6. dpdk 中设备、驱动的抽象

驱动抽象结构：

```c
struct rte_driver {
    RTE_TAILQ_ENTRY(rte_driver) next; /**< Next in list. */
    const char *name;                   /**< Driver name. */
    const char *alias;              /**< Driver alias. */
};
```

此结构主要特点：

1. 多个驱动之间通过链表链接起来
2. 驱动有唯一的名称并支持创建别名


设备抽象结构：

```c
struct rte_device {
    RTE_TAILQ_ENTRY(rte_device) next; /**< Next device */
    const char *name;             /**< Device name */
    const char *bus_info;         /**< Device bus specific information */
    const struct rte_driver *driver; /**< Driver assigned after probing */
    const struct rte_bus *bus;    /**< Bus handle assigned on scan */
    int numa_node;                /**< NUMA node connection */
    struct rte_devargs *devargs;  /**< Arguments for latest probing */
};
```

此结构主要特点：

1. 多个设备之间通过链表链接起来
2. 设备有唯一的名称
3. 设备有挂入的总线及总线信息
4. 设备有绑定的设备驱动
5. 设备有所在的 numa 节点与配置参数等属性
7. dpdk 中总线与驱动、设备的关系

总线负责扫描设备，创建设备结构并将设备挂入到特定的总线上，驱动也向特定的总线上注册。总线负责匹配设备驱动并调用驱动实现的 probe、remove 方法来初始化、移除设备。

总线的注册顺序由总线实例库的链接顺序决定，当一个平台使用支持多种总线的设备，例如（pci 网卡与 dpaa 网卡）时，链接总线库的顺序决定了设备的枚举顺序，进而影响到每个设备在 dpdk 中 port_id 的布局。

## pci 总线、pci 设备、pci 驱动

pci 总线结构:

```c
struct rte_pci_bus {
    struct rte_bus bus;               /**< Inherit the generic class */
    RTE_TAILQ_HEAD(, rte_pci_device) device_list; /**< List of PCI devices */
    RTE_TAILQ_HEAD(, rte_pci_driver) driver_list; /**< List of PCI drivers */
};
```

此结构继承 rte_bus 总线基类并扩展了 pci 设备链表与驱动链表的表头。

pci 设备结构:

```c
struct rte_pci_device {
    RTE_TAILQ_ENTRY(rte_pci_device) next;   /**< Next probed PCI device. */
    struct rte_device device;           /**< Inherit core device */
    struct rte_pci_addr addr;           /**< PCI location. */
    struct rte_pci_id id;               /**< PCI ID. */
    struct rte_mem_resource mem_resource[PCI_MAX_RESOURCE];
                        /**< PCI Memory Resource */
    struct rte_intr_handle *intr_handle; /**< Interrupt handle */
    struct rte_pci_driver *driver;      /**< PCI driver used in probing */
    uint16_t max_vfs;                   /**< sriov enable if not zero */
    enum rte_pci_kernel_driver kdrv;    /**< Kernel driver passthrough */
    char name[PCI_PRI_STR_SIZE+1];      /**< PCI location (ASCII) */
    char *bus_info;                     /**< PCI bus specific info */
    struct rte_intr_handle *vfio_req_intr_handle;
                /**< Handler of VFIO request a */
};
```

此结构继承 rte_device 设备基类，此结构代表的 pci 设备之间通过链表组织起来，每个 pci 设备有其唯一标识（pci 号）以及 pci 内存资源空间等重要成员，并保存了此设备所在的总线与绑定到的驱动，便于快速从一个设备结构获取到其所在总线的 rte_bus 结构与 rte_driver 结构。

pci 驱动结构:

```c
struct rte_pci_driver {
    RTE_TAILQ_ENTRY(rte_pci_driver) next;  /**< Next in list. */
    struct rte_driver driver;          /**< Inherit core driver. */
    rte_pci_probe_t *probe;            /**< Device probe function. */
    rte_pci_remove_t *remove;          /**< Device remove function. */
    pci_dma_map_t *dma_map;        /**< device dma map function. */
    pci_dma_unmap_t *dma_unmap;    /**< device dma unmap function. */
    const struct rte_pci_id *id_table; /**< ID table, NULL terminated. */
    uint32_t drv_flags;                /**< Flags RTE_PCI_DRV_*. */
};
```

此结构继承 rte_driver 基类，此结构描述了一个 pci 驱动支持的网卡列表及设备的 probe、remove、dma 映射相关方法。

# 总结

新 dpdk 用户态驱动框架中引入了 rte_bus 总线抽象结构，此结构的引入为 dpdk 用户态驱动框架增加了一个新的层次，总线、设备、驱动这三个结构的关系变得清晰，似乎更接近 linux 内核驱动框架的原理了。