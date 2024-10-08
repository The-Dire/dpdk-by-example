# dpdk-by-example
dpdk实战例子学习指南

### 1.dpdk实现简单服务器以及核心api总结

[1.dpdk环境虚拟机安装](doc/first/01_dpdk_env.md)

[2.dpdk实现网卡接收数据包并解析udp包](doc/first/02_dpdk_udp_recv.md) --- 代码在src/example/01_recv

[3.dpdk实现udp echo服务器](doc/first/03_dpdk_echo_server.md)  --- 代码在src/example/02_udp_echo_server

[4.dpdk实现arp响应和icmp的reply](doc/first/04_arp_request_response.md)  --- 代码在src/example/03_arp和04_icmp

[5.实现arp广播以及arp表相关功能](doc/first/05_arp_table.md) --- 代码在src/example/05_arptable

[6.利用DPDK队列实现基础协议栈(什么是协议栈)](doc/first/06_dpdk_netstack.md) --- 代码在src/example/06_netarch

[7.实现socket层并使用socekt实现udp服务器](doc/first/07_dpdk_impl_udp_sock.md) --- 代码在src/example/07_udp

[8.协议栈完结篇:实现tcp socket](doc/first/08_tcp_impl.md) -- 代码在src/example/08_tcp

[9.dpdk常用核心api使用教程](doc/first/09_dpdk_api.md)

[补充:arp基础知识](doc/first/arp_basic.md)

[10G网卡的最大包转发率是怎么算出来的(包转发率)](doc/first/pps_compute.md)

### 2.dpdk涉及到的基础知识

[1.网络虚拟化知识扫盲](doc/basic/00_virtual_basic.md) -- 源码分析中会详解dpdk怎么实现virtio驱动的

[2.numa知识扫盲](doc/basic/01_numa_basic.md)

[3.dpdk怎么确定网卡rx与tx描述符](doc/basic/02_dpdk_tx_rx_config.md)

[4.dpdk内存均分优化实现分析](doc/basic/03_dpdk_mem_manager_optimize.md)

[5.simd初探](doc/basic/04_simd_beginner.md)

[5.1 intel simd常用api附录](doc/basic/04_simd_intel_api.md)

simd收发包的优化可以参考DPDK的virtio_rxtx_simple_sse.c和virtio_rxtx_simple_neon.c这两个文件。

[6.dpdk常用结构TAILQ使用浅析](doc/basic/05_dpdk_tailq.md)

### 3.dpdk官方案例源码分析

[1.dpdk多线程浅析及其Hello World程序详解](doc/example_doc/01_dpdk_multi_threads.md)

[2.dpdk l2fwd源码分析](doc/example_doc/l2fwd.md)

[3.dpdk lpm算法分析](doc/example_doc/dpdk_lpm.md)

有部分源码没写文档，因为比较重复只添加了注释可以自行查看。[dpdk example](example-code)

### 4.dpdk源码分析

[0.dpdk igb_uio实现分析](doc/source_doc/00_igb_uio.md)

[1.dpdk初始化实现分析](doc/source_doc/01_dpdk_init.md)

[2.1.dpdk物理网卡收发包实现分析](doc/source_doc/02_1_dpdk_rxtx.md)

[2.2.dpdk虚拟网卡收发包实现分析](doc/source_doc/02_2_dpdk_virtio.md)

[3.dpdk DMA收发包过程分析](doc/source_doc/03_dpdk_dma_process.md)

[4.dpdk解初始化实现分析](doc/source_doc/04_dpdk_ubind.md)

[5.rte_mbuf实现分析](doc/source_doc/05_dpdk_rte_mbuf.md)

[6.DPDK网卡控制api实现分析](doc/source_doc/06_dpdk_eth_control.md)

[7.DPDK用户态驱动总线框架浅析](doc/source_doc/07_dpdk_bus_framework.md)

[8.DPDK ring多生产多消费者无锁原理分析](doc/source_doc/08_dpdk_ring_lock_free.md)

## 杂项

[1.定制dpdk驱动(以修改设备mvpp2和pcie总线加载顺序为例)](doc/work_note/01_dpdk_modify_bus_load.md)

[2.修改驱动和应用代码以支持网卡热插拔](doc/work_note/02_dpdk_network_hot_swapping.md)

[3.新网卡移植dpdk驱动的流程](doc/work_note/03_dpdk_device_install.md)