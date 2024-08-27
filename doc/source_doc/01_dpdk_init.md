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

### 3.1 注册设备驱动到rte_pci_bus.driver_list

1. pci总线管理结构初始化driver_list

首先DPDK使用rte_pci_bus这个全局变量来管理所有pci网卡驱动。

dpdk pci初始化driver_list链表的代码如下:

代码在drivers\bus\pci\pci_common.c内部

```c
struct rte_pci_bus rte_pci_bus = {
	.bus = {
		.scan = rte_pci_scan,
		.probe = rte_pci_probe,
		.find_device = pci_find_device,
		.plug = pci_plug,
		.unplug = pci_unplug,
		.parse = pci_parse,
		.dma_map = pci_dma_map,
		.dma_unmap = pci_dma_unmap,
		.get_iommu_class = rte_pci_get_iommu_class,
		.dev_iterate = rte_pci_dev_iterate,
		.hot_unplug_handler = pci_hot_unplug_handler,
		.sigbus_handler = pci_sigbus_handler,
	},
	.device_list = TAILQ_HEAD_INITIALIZER(rte_pci_bus.device_list),
	.driver_list = TAILQ_HEAD_INITIALIZER(rte_pci_bus.driver_list),
};

RTE_REGISTER_BUS(pci, rte_pci_bus.bus);
```

其中`.driver_list = TAILQ_HEAD_INITIALIZER(rte_pci_bus.driver_list),`则是初始化pci总线的driver_list链表。

从bus文件夹中可以得知，dpdk支持dpaa，fslmc，ifpga，pci，vdev，vmbus这6种pci总线。其余总线注册设备驱动到对应的总线的`driver_list`流程是一样的。

2. 注册DPDK PMD驱动然后挂在到`driver_list`上面

以ixgbe为例，下面代码都在drivers\net\ixgbe\ixgbe_ethdev.c能找到。

```c
// probe ixgbe驱动
static struct rte_pci_driver rte_ixgbe_pmd = {
	.id_table = pci_id_ixgbe_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ixgbe_pci_probe,
	.remove = eth_ixgbe_pci_remove,
};
```

上述代码就代表ixgbe实现了其对应的驱动。

下面的代码则是将实现了的驱动注册到DPDK整个框架里。

```c
RTE_PMD_REGISTER_PCI(net_ixgbe, rte_ixgbe_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ixgbe, pci_id_ixgbe_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ixgbe, "* igb_uio | uio_pci_generic | vfio-pci");
```

其中核心是`RTE_PMD_REGISTER_PCI`宏。

```c
/** Helper for PCI device registration from driver (eth, crypto) instance */
#define RTE_PMD_REGISTER_PCI(nm, pci_drv) \
RTE_INIT(pciinitfn_ ##nm) \
{\
	(pci_drv).driver.name = RTE_STR(nm);\
	rte_pci_register(&pci_drv); \
} \
RTE_PMD_EXPORT_NAME(nm, __COUNTER__)
```

该宏调用了`rte_pci_register`函数，作用就是把这个驱动注册到`rte_pci_bus.driver_list`中。

```c
void
rte_pci_register(struct rte_pci_driver *driver)
{
	TAILQ_INSERT_TAIL(&rte_pci_bus.driver_list, driver, next);
	driver->bus = &rte_pci_bus;
}
```

这里要明确一点注册设备驱动的过程在main函数执行之前完成。 这样就有了设备驱动类型、设备驱动的初始化函数。在老版本DPDK 16.04及之前使用了GNU C提供的“attribute（constructor）”机制来保证注册驱动在前。

新版本通过`RTE_REGISTER_BUS`宏机制保证了注册驱动在main函数之前。

### 3.2 扫描系统中的PCI设备,并注册到rte_pci_bus.device_list

实质上，DPDK通过Linux内核提供的文件系统 /sys/bus/pci 来扫描PCI总线上的内容。

device_list链表节点结构为:

```c
/**
 * A structure describing a PCI device.
 */
struct rte_pci_device {
	TAILQ_ENTRY(rte_pci_device) next;   /**< Next probed PCI device. */
	struct rte_device device;           /**< Inherit core device */
	struct rte_pci_addr addr;           /**< PCI location. */
	struct rte_pci_id id;               /**< PCI ID. */
	struct rte_mem_resource mem_resource[PCI_MAX_RESOURCE];
					    /**< PCI Memory Resource */
	struct rte_intr_handle intr_handle; /**< Interrupt handle */
	struct rte_pci_driver *driver;      /**< PCI driver used in probing */
	uint16_t max_vfs;                   /**< sriov enable if not zero */
	enum rte_kernel_driver kdrv;        /**< Kernel driver passthrough */
	char name[PCI_PRI_STR_SIZE+1];      /**< PCI location (ASCII) */
	struct rte_intr_handle vfio_req_intr_handle;
				/**< Handler of VFIO request interrupt */
};
```

从系统中获取到PCI设备的相关信息后，记录到这样的一个结构体中。

如何获取到这些信息： 在main函数的一开始，调用`rte_eal_init()`获取用户、系统的相关配置信息以及设置基础运行环境。

其中调用`rte_bus_scan()`来扫描、获取系统中的网卡信息；老版本这里的调用是`rte_eal_pci_init()`。新版本将DPDK所有总线做了整合。


下面看详细代码:
```c
/* Scan all the buses for registered devices */
int
rte_bus_scan(void)
{
	int ret;
	struct rte_bus *bus = NULL;

	TAILQ_FOREACH(bus, &rte_bus_list, next) {
		ret = bus->scan();
		if (ret)
			RTE_LOG(ERR, EAL, "Scan for (%s) bus failed.\n",
				bus->name);
	}

	return 0;
}
```

遍历`rte_bus_list`链表，当此时为pci总线的时候，执行`struct rte_pci_bus rte_pci_bus`注册的scan函数`rte_pci_scan`。

首先，执行`.device_list = TAILQ_HEAD_INITIALIZER(rte_pci_bus.device_list),`初始化了rte_pci_bus.device_list链表，后面扫描的到的pci网卡设备信息会记录到这个链表中； 然后，调用`rte_pci_scan()`扫描系统中的PCI网卡：遍历 “/sys/bus/pci/devices”目录下的所有pci地址，逐个获取对应的pci地址、pci id、sriov使能时的vf个数、亲和的numa、设备地址空间、驱动类型等；

具体函数如下:

```c
/*
 * Scan the content of the PCI bus, and the devices in the devices
 * list
 */
int
rte_pci_scan(void)
{
	struct dirent *e;
	DIR *dir;
	char dirname[PATH_MAX];
	struct rte_pci_addr addr;

	/* for debug purposes, PCI can be disabled */
	if (!rte_eal_has_pci())
		return 0;

#ifdef VFIO_PRESENT
	if (!pci_vfio_is_enabled())
		RTE_LOG(DEBUG, EAL, "VFIO PCI modules not loaded\n");
#endif
	// linux一般来说打开/sys/bus/pci/devices路径
	dir = opendir(rte_pci_get_sysfs_path());
	if (dir == NULL) {
		RTE_LOG(ERR, EAL, "%s(): opendir failed: %s\n",
			__func__, strerror(errno));
		return -1;
	}

	while ((e = readdir(dir)) != NULL) {
		if (e->d_name[0] == '.')
			continue;

		if (parse_pci_addr_format(e->d_name, sizeof(e->d_name), &addr) != 0)
			continue;

		snprintf(dirname, sizeof(dirname), "%s/%s",
				rte_pci_get_sysfs_path(), e->d_name);
		// 实际pci信息获取
		if (pci_scan_one(dirname, &addr) < 0)
			goto error;
	}
	closedir(dir);
	return 0;

error:
	closedir(dir);
	return -1;
}
```

实际获取pci信息，然后填充到devices list链表的函数`pci_scan_one()`如下:

```c
/* Scan one pci sysfs entry, and fill the devices list from it. */
static int
pci_scan_one(const char *dirname, const struct rte_pci_addr *addr)
{
	char filename[PATH_MAX];
	unsigned long tmp;
	struct rte_pci_device *dev;
	char driver[PATH_MAX];
	int ret;

	dev = malloc(sizeof(*dev));
	if (dev == NULL)
		return -1;

	memset(dev, 0, sizeof(*dev));
	dev->device.bus = &rte_pci_bus.bus;
	dev->addr = *addr;

	/* 获取厂商id */
	snprintf(filename, sizeof(filename), "%s/vendor", dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.vendor_id = (uint16_t)tmp;

	/* 获取设备号 */
	snprintf(filename, sizeof(filename), "%s/device", dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.device_id = (uint16_t)tmp;

	/* 获取subsystem_vendor id */
	snprintf(filename, sizeof(filename), "%s/subsystem_vendor",
		 dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.subsystem_vendor_id = (uint16_t)tmp;

	/* 获取subsystem_device id */
	snprintf(filename, sizeof(filename), "%s/subsystem_device",
		 dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	dev->id.subsystem_device_id = (uint16_t)tmp;

	/* 获取 class_id,class id表明该pci设备的类型 */
	snprintf(filename, sizeof(filename), "%s/class",
		 dirname);
	if (eal_parse_sysfs_value(filename, &tmp) < 0) {
		free(dev);
		return -1;
	}
	/* the least 24 bits are valid: class, subclass, program interface */
	dev->id.class_id = (uint32_t)tmp & RTE_CLASS_ANY_ID;

	/* 获取最大vfs数 max_vfs */
	dev->max_vfs = 0;
	snprintf(filename, sizeof(filename), "%s/max_vfs", dirname);
	if (!access(filename, F_OK) &&
	    eal_parse_sysfs_value(filename, &tmp) == 0)
		dev->max_vfs = (uint16_t)tmp;
	else {
		/* for non igb_uio driver, need kernel version >= 3.8 */
		snprintf(filename, sizeof(filename),
			 "%s/sriov_numvfs", dirname);
		if (!access(filename, F_OK) &&
		    eal_parse_sysfs_value(filename, &tmp) == 0)
			dev->max_vfs = (uint16_t)tmp;
	}
	// 获取亲和的numa，默认id为0
	/* get numa node, default to 0 if not present */
	snprintf(filename, sizeof(filename), "%s/numa_node",
		 dirname);

	if (access(filename, F_OK) != -1) {
		if (eal_parse_sysfs_value(filename, &tmp) == 0)
			dev->device.numa_node = tmp;
		else
			dev->device.numa_node = -1;
	} else {
		dev->device.numa_node = 0;
	}

	pci_name_set(dev);

	/* parse resources */
	snprintf(filename, sizeof(filename), "%s/resource", dirname);
	if (pci_parse_sysfs_resource(filename, dev) < 0) {
		RTE_LOG(ERR, EAL, "%s(): cannot parse resource\n", __func__);
		free(dev);
		return -1;
	}

	/* parse driver */
	snprintf(filename, sizeof(filename), "%s/driver", dirname);
	ret = pci_get_kernel_driver_by_path(filename, driver, sizeof(driver));
	if (ret < 0) {
		RTE_LOG(ERR, EAL, "Fail to get kernel driver\n");
		free(dev);
		return -1;
	}

	if (!ret) {
		if (!strcmp(driver, "vfio-pci"))
			dev->kdrv = RTE_KDRV_VFIO;
		else if (!strcmp(driver, "igb_uio"))
			dev->kdrv = RTE_KDRV_IGB_UIO;
		else if (!strcmp(driver, "uio_pci_generic"))
			dev->kdrv = RTE_KDRV_UIO_GENERIC;
		else
			dev->kdrv = RTE_KDRV_UNKNOWN;
	} else
		dev->kdrv = RTE_KDRV_NONE;

	/* device is valid, add in list (sorted) */
	if (TAILQ_EMPTY(&rte_pci_bus.device_list)) {
		rte_pci_add_device(dev);
	} else {
		struct rte_pci_device *dev2;
		int ret;

		TAILQ_FOREACH(dev2, &rte_pci_bus.device_list, next) {
			ret = rte_pci_addr_cmp(&dev->addr, &dev2->addr);
			if (ret > 0)
				continue;

			if (ret < 0) {
				rte_pci_insert_device(dev2, dev);
			} else { /* already registered */
				if (!rte_dev_is_probed(&dev2->device)) {
					dev2->kdrv = dev->kdrv;
					dev2->max_vfs = dev->max_vfs;
					pci_name_set(dev2);
					memmove(dev2->mem_resource,
						dev->mem_resource,
						sizeof(dev->mem_resource));
				} else {
					/**
					 * If device is plugged and driver is
					 * probed already, (This happens when
					 * we call rte_dev_probe which will
					 * scan all device on the bus) we don't
					 * need to do anything here unless...
					 **/
					if (dev2->kdrv != dev->kdrv ||
						dev2->max_vfs != dev->max_vfs)
						/*
						 * This should not happens.
						 * But it is still possible if
						 * we unbind a device from
						 * vfio or uio before hotplug
						 * remove and rebind it with
						 * a different configure.
						 * So we just print out the
						 * error as an alarm.
						 */
						RTE_LOG(ERR, EAL, "Unexpected device scan at %s!\n",
							filename);
				}
				free(dev);
			}
			return 0;
		}
		// 添加该pci设备到链表里
		rte_pci_add_device(dev);
	}

	return 0;
}
```

简言之，上述函数扫描并记录了系统中所有的pci设备的相关信息，后面根据上面获取的这些设备信息以及前面注册的驱动信息，就可以完成具体网卡设备的初始化。

### 3.3 初始化注册的驱动

在`rte_eal_init()`函数中，后面会调用`rte_bus_probe()`（老版本是`rte_eal_dev_init()`）来初始化前面注册的驱动device_list：分别调用注册的每款驱动的初始化函数(probe函数)。把每款驱动的一些信息记录到对应总线的driver_list链表中。

以pci为例，链表节点为：

```c
/**
 * A structure describing a PCI driver.
 */
struct rte_pci_driver {
	TAILQ_ENTRY(rte_pci_driver) next;  /**< Next in list. */
	struct rte_driver driver;          /**< Inherit core driver. */
	struct rte_pci_bus *bus;           /**< PCI bus reference. */
	pci_probe_t *probe;                /**< Device Probe function. */
	pci_remove_t *remove;              /**< Device Remove function. */
	pci_dma_map_t *dma_map;		   /**< device dma map function. */
	pci_dma_unmap_t *dma_unmap;	   /**< device dma unmap function. */
	const struct rte_pci_id *id_table; /**< ID table, NULL terminated. */
	uint32_t drv_flags;                /**< Flags RTE_PCI_DRV_*. */
};
```

该结构记录了驱动支持的网卡设备的verder id、device id信息，这个在后面具体的PCI网卡设备初始化时，会根据这些信息来匹配驱动。

其中该结构中的`rte_pci_id`就是用来匹配驱动的。

```c
/**
 * A structure describing an ID for a PCI driver. Each driver provides a
 * table of these IDs for each device that it supports.
 */
struct rte_pci_id {
	uint32_t class_id;            /**< Class ID or RTE_CLASS_ANY_ID. */
	uint16_t vendor_id;           /**< Vendor ID or PCI_ANY_ID. */
	uint16_t device_id;           /**< Device ID or PCI_ANY_ID. */
	uint16_t subsystem_vendor_id; /**< Subsystem vendor ID or PCI_ANY_ID. */
	uint16_t subsystem_device_id; /**< Subsystem device ID or PCI_ANY_ID. */
};
```

以`eth_ixgbe_dev_init`函数为例(函数在drivers\net\ixgbe\ixgbe_ethdev.c中)，会通过`device_id`或`vendor_id`进行不同的设置。

已ixgbe类型的网卡为例，注册的信息为`rte_ixgbe_pmd`（在drivers\net\ixgbe\ixgbe_ethdev.c）：


```c
static struct rte_pci_driver rte_ixgbe_pmd = {
	.id_table = pci_id_ixgbe_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ixgbe_pci_probe,
	.remove = eth_ixgbe_pci_remove,
};
// 省略
RTE_PMD_REGISTER_PCI(net_ixgbe, rte_ixgbe_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ixgbe, pci_id_ixgbe_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ixgbe, "* igb_uio | uio_pci_generic | vfio-pci");
```

至此，注册的每款驱动的设备初始化，支持的设备等信息以及系统中所有的pci设备信息就已经都有了，分别记录在`rte_pci_bus.driver_list`和`rte_pci_bus.device_list`这两个全局的链表中，接下来就可以完成设备匹配驱动，别初始化设备了。

注:上文均以pci设备为例，dpdk支持的总线不止pci。

### 3.4 网卡设备初始化

`rte_eal_init()`函数接下来调用`rte_pci_probe()`函数完成具体的设备的初始化

```c
/*
 * Scan the content of the PCI bus, and call the probe() function for
 * all registered drivers that have a matching entry in its id_table
 * for discovered devices.
 */
int
rte_pci_probe(void)
{
	struct rte_pci_device *dev = NULL;
	size_t probed = 0, failed = 0;
	struct rte_devargs *devargs;
	int probe_all = 0;
	int ret = 0;
	/* 如果配置了白名单，只初始化白名单中的设备，否则所有支持的设备都初始化 */
	if (rte_pci_bus.bus.conf.scan_mode != RTE_BUS_SCAN_WHITELIST)
		probe_all = 1;

	FOREACH_DEVICE_ON_PCIBUS(dev) {
		probed++;

		devargs = dev->device.devargs;
		/* probe all or only whitelisted devices */
		if (probe_all)
			ret = pci_probe_all_drivers(dev);
		else if (devargs != NULL &&
			devargs->policy == RTE_DEV_WHITELISTED)
			ret = pci_probe_all_drivers(dev);
		if (ret < 0) {
			if (ret != -EEXIST) {
				RTE_LOG(ERR, EAL, "Requested device "
					PCI_PRI_FMT " cannot be used\n",
					dev->addr.domain, dev->addr.bus,
					dev->addr.devid, dev->addr.function);
				rte_errno = errno;
				failed++;
			}
			ret = 0;
		}
	}

	return (probed && probed == failed) ? -1 : 0;
}
```

`pci_probe_all_drivers()`函数probe所有具体的设备。

实际某个设备的probe的调用为`rte_pci_probe_one_driver()`，这个函数主要做的事情是：比较vendor id、device id，然后映射设备资源、调用驱动的设备初始化函数：

```c
/*
 * If vendor/device ID match, call the probe() function of the
 * driver.
 */
static int
rte_pci_probe_one_driver(struct rte_pci_driver *dr,
			 struct rte_pci_device *dev)
{
	int ret;
	bool already_probed;
	struct rte_pci_addr *loc;

	if ((dr == NULL) || (dev == NULL))
		return -EINVAL;

	loc = &dev->addr;
	// 设备不在黑名单里，检查驱动是否支持
	/* The device is not blacklisted; Check if driver supports it */
	if (!rte_pci_match(dr, dev))
		/* Match of device and driver failed */
		return 1;

	RTE_LOG(INFO, EAL, "PCI device "PCI_PRI_FMT" on NUMA socket %i\n",
			loc->domain, loc->bus, loc->devid, loc->function,
			dev->device.numa_node);
	// 设备命中黑名单，直接返回
	/* no initialization when blacklisted, return without error */
	if (dev->device.devargs != NULL &&
		dev->device.devargs->policy ==
			RTE_DEV_BLACKLISTED) {
		RTE_LOG(INFO, EAL, "  Device is blacklisted, not"
			" initializing\n");
		return 1;
	}
	// 设备未分配numa节点，直接返回
	if (dev->device.numa_node < 0) {
		RTE_LOG(WARNING, EAL, "  Invalid NUMA socket, default to 0\n");
		dev->device.numa_node = 0;
	}
	// 检查是否已经probe
	already_probed = rte_dev_is_probed(&dev->device);
	if (already_probed && !(dr->drv_flags & RTE_PCI_DRV_PROBE_AGAIN)) {
		RTE_LOG(DEBUG, EAL, "Device %s is already probed\n",
				dev->device.name);
		return -EEXIST;
	}

	RTE_LOG(INFO, EAL, "  probe driver: %x:%x %s\n", dev->id.vendor_id,
		dev->id.device_id, dr->driver.name);

	/* 这需要在 rte_pci_map_device() 之前，因为它允许使用驱动程序标志来调整配置。
	 * reference driver structure
	 * This needs to be before rte_pci_map_device(), as it enables to use
	 * driver flags for adjusting configuration.
	 */
	if (!already_probed) {
		enum rte_iova_mode dev_iova_mode;
		enum rte_iova_mode iova_mode;

		dev_iova_mode = pci_device_iova_mode(dr, dev);
		iova_mode = rte_eal_iova_mode();
		if (dev_iova_mode != RTE_IOVA_DC &&
		    dev_iova_mode != iova_mode) {
			RTE_LOG(ERR, EAL, "  Expecting '%s' IOVA mode but current mode is '%s', not initializing\n",
				dev_iova_mode == RTE_IOVA_PA ? "PA" : "VA",
				iova_mode == RTE_IOVA_PA ? "PA" : "VA");
			return -EINVAL;
		}

		dev->driver = dr;
	}

	if (!already_probed && (dr->drv_flags & RTE_PCI_DRV_NEED_MAPPING)) {
		/* map resources for devices that use igb_uio */
		ret = rte_pci_map_device(dev); // 使用 igb_uio 的设备的映射资源
		if (ret != 0) {
			dev->driver = NULL;
			return ret;
		}
	}
	// 调用驱动的probe函数
	/* call the driver probe() function */
	ret = dr->probe(dr, dev);
	if (already_probed)
		return ret; /* no rollback if already succeeded earlier */
	if (ret) {
		dev->driver = NULL;
		if ((dr->drv_flags & RTE_PCI_DRV_NEED_MAPPING) &&
			/* Don't unmap if device is unsupported and
			 * driver needs mapped resources.
			 */
			!(ret > 0 &&
				(dr->drv_flags & RTE_PCI_DRV_KEEP_MAPPED_RES)))
			rte_pci_unmap_device(dev);
	} else {
		dev->device.driver = &dr->driver;
	}

	return ret;
}
```

`rte_pci_map_device(dev)`函数内部调用`pci_uio_map_resource(dev)`为pci设备在虚拟地址空间映射pci资源，后续直接通过操作内存来操作pci设备；

pci_uio_map_resource的逻辑:

1. 如果是dpdk secondary进程不进行分配直接复用
2. 分配uio所需内存
3. 映射网卡设备的所有BARs

旧版本的DPDK的驱动的设备初始化函数`rte_eth_dev_init()`主要是初始化dpdk驱动框架中，为每个设备分配资源以及资源的初始化。

新版本以总线类型做了划分，以pci为例，驱动的设备初始化函数为`rte_eth_dev_pci_generic_probe()`,这个函数会在probe调用的时候进行执行。

这里说明下，老版本注册driver为如下,以DPDK 16.04为例:

```c
static struct rte_driver rte_bnx2x_driver = {
	.type = PMD_PDEV,
	.init = rte_bnx2x_pmd_init,
};
```

新版本直接probe了。

```c
static struct rte_pci_driver rte_ixgbe_pmd = {
	.id_table = pci_id_ixgbe_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ixgbe_pci_probe,
	.remove = eth_ixgbe_pci_remove,
};
```

`eth_ixgbe_pci_probe`中是直接通过代码为ixgbe设备分配资源以及资源的初始化的。具体参照`struct rte_eth_dev *pf_ethdev;`变量被执行的操作。


以ixbgevf为例,则是直接调用了`rte_eth_dev_pci_generic_probe`为ixgbevf设备分配资源以及资源的初始化。

```c
static int eth_ixgbevf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct ixgbe_adapter), eth_ixgbevf_dev_init);
}
```

```c
/* 每个设备对应数组的一个成员，记录了设备相关的所有信息 */
struct rte_eth_dev rte_eth_devices[RTE_MAX_ETHPORTS];

/* 端口相关的配置 */
struct rte_eth_dev_data *dat;
```

dpdk框架中，对端口的初始化操作已经基本完成，后面则是根据用户的设置，配置端口的收发包队列以及最终start端口，开始收发包，其间的主要过程如下：

1. `rte_eth_dev_configure()`函数完成端口配置：队列数配置、RSS、offload等等设置；
2. `rte_eth_rx_queue_setup()`、`rte_eth_tx_queue_setup()`函数分别设置端口的每个收发队列：ring空间申请、初始化等； 
3. `rte_eth_dev_start()`函数：发送队列初始化buf填充，端口使能(具体可以参考代码或网卡芯片手册，均是相关寄存器设置)；


# 总结

本文主要讲解了DPDK的内部多个网卡的驱动如何组织和如何添加一款交换芯片的驱动是DPDK的核心。

DPDK最重要的一点即是去除了内核与应用程序的区分，用户调用的DPDK提供的RTE库实质上就是能够直接与硬件进行交互了。(普通socket程序需要内核与硬件交互后返给该应用)。