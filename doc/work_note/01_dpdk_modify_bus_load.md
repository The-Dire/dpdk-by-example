# 特殊设备mvpp2和pcie网卡DPDK驱动加载顺序修改

Marvell CN9131设备需要导入网讯网卡，包含ngbe,txgbe两种驱动。

## 存在的问题

移植了txgbe网卡驱动后，txgbe网卡驱动设备驱动总是会优先于mvpp2网卡设备加载。由于Marvell的特殊硬件架构，需要mvpp2优先加载。

## 修改总线scan顺序

在dpdk19.11架构中有6种总线，dpaa,fslmc,pci,vdev,ifpga,vmbus。从驱动代码中可了解txgbe网卡是挂载在PCI总线上的网卡设备，mvpp2网卡是挂载在vdev总线上的设备。

由于该网卡是闭源驱动所以以用如下代码做演示：

```c
RTE_PMD_REGISTER_PCI(FPGA_LTE_FEC_PF_DRIVER_NAME, fpga_lte_fec_pci_pf_driver);
RTE_PMD_REGISTER_PCI_TABLE(FPGA_LTE_FEC_PF_DRIVER_NAME,
		pci_id_fpga_lte_fec_pf_map);
RTE_PMD_REGISTER_KMOD_DEP(FPGA_LTE_FEC_PF_DRIVER_NAME, "* igb_uio | uio_pci_generic | vfio-pci");

RTE_PMD_REGISTER_VDEV(FPGA_LTE_FEC_MVPP2_DRIVER_NAME, fpga_pmd_mrvl_drv);
RTE_PMD_REGISTER_ALIAS(FPGA_LTE_FEC_MVPP2_DRIVER_NAME, fpga_eth_mvpp2);
```

最初怀疑是PCI总线优先扫描设备，于是修改pmd驱动链接的顺序，将pci总线放置最后。并在总线扫描相关函数添加打印信息。

实际操作为: 修改文件rte.app.mk中的总线加载顺序。

原始的加载顺序如下:

```make
_LDLIBS-$(CONFIG_RTE_LIBRTE_PCI_BUS)        += -lrte_bus_pci
_LDLIBS-$(CONFIG_RTE_LIBRTE_VDEV_BUS)       += -lrte_bus_vdev
_LDLIBS-$(CONFIG_RTE_LIBRTE_DPAA_BUS)       += -lrte_bus_dpaa
ifeq ($(CONFIG_RTE_EAL_VFIO),y)
_LDLIBS-$(CONFIG_RTE_LIBRTE_FSLMC_BUS)      += -lrte_bus_fslmc
endif
```

修改为如下:

```make
_LDLIBS-$(CONFIG_RTE_LIBRTE_VDEV_BUS)       += -lrte_bus_vdev
_LDLIBS-$(CONFIG_RTE_LIBRTE_DPAA_BUS)       += -lrte_bus_dpaa
ifeq ($(CONFIG_RTE_EAL_VFIO),y)
_LDLIBS-$(CONFIG_RTE_LIBRTE_FSLMC_BUS)      += -lrte_bus_fslmc
endif
_LDLIBS-$(CONFIG_RTE_LIBRTE_PCI_BUS)        += -lrte_bus_pci
```

这样就把pci总线加载放到了最后面了。

修改`rte_bus_scan`函数为如下:

其实就是增加了一行打印。

```c
int
rte_bus_scan(void)
{
	int ret;
	struct rte_bus *bus = NULL;

	TAILQ_FOREACH(bus, &rte_bus_list, next) {
        printf("rte_bus_scan, bus name:%s\r\n", bus->name);
		ret = bus->scan();
		if (ret)
			RTE_LOG(ERR, EAL, "Scan for (%s) bus failed.\n",
				bus->name);
	}

	return 0;
}

```

本以为这样就可以了但是使用gdb调试l2fwd发现bus扫描顺序符合预期(vdev总线优先scan)，但是驱动probe的顺序依然不对。

调试命令如下:

```shell
./l2fwd -c0xd -n4 --vdev=eth_mvpp2,iface=eth0,iface=eth2,iface=eth3 --proc-type=primary --master-lcore 0 rte_bus_scan; bus name:dpaa_bus
```

程序输出:

```shell
rte_bus_scan: bus name:vdev
#省略
```

## 排查dpdk probe相关代码

经过bus扫描顺序的修改，问题依然没有解决，于是继续看代码probe部分。在`rte_pci_probe`函数打断点并查看函数调用。

找到`rte_bus_probe`函数，发现dpdk对`vbus`总线probe置后处理。

原始代码如下:

```c
/* Probe all devices of all buses */
int
rte_bus_probe(void)
{
	int ret;
	struct rte_bus *bus, *vbus = NULL;

	TAILQ_FOREACH(bus, &rte_bus_list, next) {
		if (!strcmp(bus->name, "vdev")) {
			vbus = bus;
			continue;
		}

		ret = bus->probe();
		if (ret)
			RTE_LOG(ERR, EAL, "Bus (%s) probe failed.\n",
				bus->name);
	}

	if (vbus) {
		ret = vbus->probe();
		if (ret)
			RTE_LOG(ERR, EAL, "Bus (%s) probe failed.\n",
				vbus->name);
	}

	return 0;
}
```

只需要注释掉如下代码，然后重新编译dpdk驱动就可以发现probe顺序变为修改的顺序了。

```c
if (!strcmp(bus->name, "vdev")) {
    vbus = bus;
    continue;
}
```

# 总结

需要同时修改bus部分的链接顺序以及`rte_bus_probe`函数后才能达到mvpp2驱动优先加载的目的。

修改dpdk驱动总线加载顺序需要修改两个部分。