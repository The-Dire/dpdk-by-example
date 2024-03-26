
运行参数解析:

```
-c : 设置要运行的内核的十六进制位掩码,使用-l更加直观.
-l : 要运行的核心列表.
-n : 每个CPU的内存通道数.
--  : 表示之后为次参数
-q : 每个CPU管理的队列数，这里使用默认值.
-p : PORTMASK: 要使用的端口的16进制位图，此处设置为第3个端口.
```


运行效果:

```shell
sudo ./l2fwd -l 0-3 -n 4 -- -p 0x3
EAL: Detected 4 lcore(s)
EAL: Detected 1 NUMA nodes
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'PA'
EAL: No available hugepages reported in hugepages-1048576kB
EAL: Probing VFIO support...
EAL: PCI device 0000:02:01.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 8086:100f net_e1000_em
EAL: PCI device 0000:03:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 15ad:7b0 net_vmxnet3
EAL: PCI device 0000:0b:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 15ad:7b0 net_vmxnet3
EAL: PCI device 0000:13:00.0 on NUMA socket -1
EAL:   Invalid NUMA socket, default to 0
EAL:   probe driver: 15ad:7b0 net_vmxnet3
MAC updating enabled
Lcore 0: RX port 0
Lcore 1: RX port 1
Initializing port 0... done: 
Port 0, MAC address: 00:0C:29:4F:5F:E0

Initializing port 1... done: 
Port 1, MAC address: 00:0C:29:4F:5F:EA

Skipping disabled port 2

Checking link statusdone
Port0 Link Up. Speed 10000 Mbps - full-duplex
Port1 Link Up. Speed 10000 Mbps - full-duplex
L2FWD: entering main loop on lcore 1
L2FWD:  -- lcoreid=1 portid=1
L2FWD: lcore 3 has nothing to do
L2FWD: entering main loop on lcore 0
L2FWD:  -- lcoreid=0 portid=0

Port statistics ====================================
Statistics for port 0 ------------------------------
Packets sent:                  1871351
Packets received:              1525888
Packets dropped:                     0
Statistics for port 1 ------------------------------
Packets sent:                  1525888
Packets received:              1871383
Packets dropped:                     0
Aggregate statistics ===============================
Total packets sent:            3397239
Total packets received:        3397271
Total packets dropped:               0
====================================================
^C

Signal 2 received, preparing to exit...
Closing port 0... Done
Closing port 1... Done
Bye...
```

二层转发和普通的端口转发(basicfwd)区别如下:

| feature   |              l2fwd              |                basicfwd                 |
| :-------- | :-----------------------------: | :-------------------------------------: |
| 端口数量  |  使用端口掩码来指定,支持奇数个  |      单同样通过端口掩码,只能偶数个      |
| lcore数量 |   多个,每个lcore负责一个port    |           一个,执行类似中继器           |
| 转发逻辑  |       转发时会改写mac地址       | 只能说0<->1,2<->3这样成对的port互相转发 |
| tx_buffer | 有发包缓存,收到的包会缓存到发包 |                 单元格                  |