# dpdk中的网卡控制

dpdk 的 api 接口非常多，这里只描述下网卡控制类接口的一些原理。

dpdk 网卡控制接口在 `rte_ethdev.h` 中定义，此文件中定义的接口是一个适配层，封装了对每个网卡底层 `dev_ops` 中的不同函数的调用，我以 `rte_eth_stats_get` 函数为例来分析。是这么把控制硬件的功能直接作为函数提供给用户的:

`rte_eth_stats_get` 函数代码如下：

```c
int
rte_eth_stats_get(uint16_t port_id, struct rte_eth_stats *stats)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);

	dev = &rte_eth_devices[port_id];
	memset(stats, 0, sizeof(*stats));

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->stats_get, -ENOTSUP);
	stats->rx_nombuf = dev->data->rx_mbuf_alloc_failed;
	return eth_err(port_id, (*dev->dev_ops->stats_get)(dev, stats));
}
```

此函数首先判断 port_id 是否有效，然后在当前 dev 中的`dev_ops->stats_get`存在时调用底层函数，将获取到的统计数据填充到 rte_eth_stats 结构体中，最后处理一些网卡无关的逻辑。

这里说一个简单的网卡操作函数调用实现。



```c
static struct rte_pci_driver rte_ixgbe_pmd = {
	.id_table = pci_id_ixgbe_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ixgbe_pci_probe,
	.remove = eth_ixgbe_pci_remove,
};
```

以igb为例调用栈如下，

```
eth_ixgbe_pci_probe
->
eth_ixgbe_dev_init
->
ixgbe_init_shared_code
->
ixgbe_init_ops_82599 内部 phy->ops.init = ixgbe_init_phy_ops_82599;
->
ixgbe_init_phy_ops_82599
->
ixgbe_init_mac_link_ops_82599
->
ixgbe_disable_tx_laser_multispeed_fiber
```

上述调用栈实现了ixgbe tx(发包)禁用多速光纤。然后在`ixgbe_dev_stop()`会被调用，然后`ixgbe_dev_close()`会调用`ixgbe_dev_stop()`。

`eth_dev_ops ixgbe_eth_dev_ops`中注册的设备关闭函数即为`ixgbe_dev_close()`。

最后dpdk提供给用户关闭网卡的函数为:

```c
void
rte_eth_dev_close(uint16_t port_id)
{
    // ......
	(*dev->dev_ops->dev_close)(dev);
    // .......
}
```

这里面的`dev_close`如果是ixgbe网卡执行的函数为`ixgbe_dev_close()`，在这里面实现了禁用多速光纤。

看起来很复杂，实际上和一般的网卡驱动实现一般无二。

下面再看一个网卡down操作

rte_eth_dev_set_link_down
->*dev->dev_ops->dev_set_link_down
->eth_dev_ops ixgbe_eth_dev_ops中注册的dev_set_link_down
->ixgbe_dev_set_link_down
->ixgbe_disable_tx_laser
->hw->mac.ops.disable_tx_laser
->其中hw->mac.ops.disable_tx_laser为函数ixgbe_disable_tx_laser_multispeed_fiber

同样用到了`ixgbe_disable_tx_laser_multispeed_fiber`。

其它网卡控制层的函数原理类似，不再赘述。