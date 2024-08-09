# 如何确定dpdk⽹卡rx描述符与tx 描述符配置

dpdk收发包描述符⼤⼩确定流程

## 1.优先使⽤驱动内部默认值，默认值不符合要求则单独调优


使用默认值的操作非常简单:`rte_eth_rx_queue_setup`调用时`nb_rx_desc`参数设置为0和`rte_eth_tx_queue_setup`配置时`nb_tx_desc`设置为0。
 
此时dpdk内部会根据不同⽹卡类型获取驱动缺省配置进⾏设置，如果驱动未提供缺省值，则使⽤全局默认值，这些配置值都是最优配置。

## 2.默认配置不满⾜，单独调优确定

1. 保持收包描述符⼤⼩不变，修改配置⽂件，按照64 128 256 512 1024 2048 4096 ⼤⼩逐次调整发包描述符，测试性能情况，取最优值
2. 保持发包描述符⼤⼩不变，修改配置⽂件，按照64 128 256 512 1024 2048 4096 ⼤⼩逐次调整收包描述符，测试性能情况，取最优值
3. 组合收发包描述符数量，测试性能情况，取最优

注意事项：
1. 收包描述符⼀般为发包描述符数量的2倍
2. 带宽更⾼的⽹卡⼀般需要配置更⼤数量的收发包描述符数⽬

## 3.驱动内部修改适配自研网卡

```shell
[dpdk-19.08-git]$grep -R -H -n 'default_rxportconf.ring_size' ./drivers/net/i40e/
./drivers/net/i40e/i40e_ethdev.c:3593:			dev_info->default_rxportconf.ring_size = 2048;
./drivers/net/i40e/i40e_ethdev.c:3595:			dev_info->default_rxportconf.ring_size = 1024;
./drivers/net/i40e/i40e_ethdev.c:3606:		dev_info->default_rxportconf.ring_size = 256;
./drivers/net/i40e/i40e_ethdev.c:3614:			dev_info->default_rxportconf.ring_size = 512;
./drivers/net/i40e/i40e_ethdev.c:3617:			dev_info->default_rxportconf.ring_size = 256                 
 [dpdk-19.08-git]$  grep -R -H -n 'default_txportconf.ring_size' ./drivers/net/i40e/
./drivers/net/i40e/i40e_ethdev.c:3597:			dev_info->default_txportconf.ring_size = 1024;
./drivers/net/i40e/i40e_ethdev.c:3599:			dev_info->default_txportconf.ring_size = 512;
./drivers/net/i40e/i40e_ethdev.c:3607:		dev_info->default_txportconf.ring_size = 256;
./drivers/net/i40e/i40e_ethdev.c:3615:			dev_info->default_txportconf.ring_size = 256;
./drivers/net/i40e/i40e_ethdev.c:3618:			dev_info->default_txportconf.ring_size = 256;        
```

此时可以直接通过修改驱动代码，更改默认值。

下面是根据搜索结果统计的配置表格:

|  网卡类型  | 收发包队列数目 | 收包描述符个数 | 发包描述符个数 |
| :--------: | :------------: | :------------: | :------------: |
| 40G XL710  |       1        |      2048      |      1024      |
| 40G XL710  |       2        |      1024      |      512       |
| 25G XXV710 |       1        |      256       |      256       |
| 10G XL710  |       1        |      512       |      256       |
|  1G XL710  |       1        |      256       |      256       |

40G XL710存在两种模式。如果使用XL710系列网卡按如上表格所示配置即可。