# dpdkcap源码分析

dpdkcap的功能是从网卡收包并写入为pcap格式文件的一个软件。要测试dpdk的性能可以采用一台主机发包另外一台主机运行dpdkcap抓包来进行测试，其中suricata的dpdk mode和dpdkcap的代码逻辑是类似的，可见其适用性。

# dpdkcap的使用

首先要知道dpdkcap如何用，下面就是一个范例。

```shell
sudo ./dpdkcap -l 0-3 -n 4 -- -p 0x3 -- --statistics --no-compression
```

-l参数：要运行的核心列表，这里是cpu
-n参数：
-p参数：
--statistics参数：
--no-compression参数：