# NUMA扫盲

DPDK为什么分配收发包队列的时候需要传入参数`rte_eth_dev_socket_id(portid)`?该参数返回以太网设备连接的 NUMA 套接字。而合理利用NUMA等计算机体系的特性即是DPDK性能高的原因。

## 1.NUMA理论

NUMA (Non-Uniform Memory Access) 是一种计算机体系结构设计的方式，旨在解决多处理器系统中内存访问的性能问题。在传统的对称多处理器（SMP）系统中，每个处理器核心都可以直接访问共享的物理内存，所有内存模块的访问延迟是相同的。然而，在具有大量处理器核心和内存的系统中，由于物理限制和电气信号传输的速度，处理器与内存之间的距离可能不同，导致访问延迟不均匀。

NUMA 架构通过在系统中引入多个节点（node），每个节点包含一组处理器核心和本地内存，来解决这个问题。每个节点都是一个自治的处理单元，具有自己的处理器核心和内存。处理器可以直接访问本地节点的内存，但要访问其他节点的内存，则需要通过互连网络进行通信。

在 NUMA 系统中，每个任务或进程被分配到一个节点上执行，并且尽量让任务使用本地节点的内存资源。这样可以减少跨节点的访问延迟，提高性能。同时，NUMA 系统还提供了一些软件和硬件机制，如远程访问优化、数据局部性管理等，以优化内存访问的效率。

NUMA 在大规模多处理器系统和服务器中得到广泛应用，特别是对于需要高性能和低延迟的任务，如科学计算、数据库等。它可以提供更好的可扩展性、内存访问效率和系统吞吐量，从而满足高性能计算和大规模数据处理的需求。

## 2.NUMA功能控制

在 Linux 内核中，控制 NUMA（Non-Uniform Memory Access）并启用 NUMA 的主要方式是通过一些参数和功能的配置。

### 2.1 内核启动参数

启动 NUMA：在启动 Linux 内核时，可以使用 boot 参数来启用 NUMA。常见的参数包括 numa=on 或者 numa=off，其中 numa=on 表示启用 NUMA，numa=off 表示禁用 NUMA。

### 2.2 内核编译选项

内核编译选项：Linux 内核编译时，可以选择启用 NUMA 相关的选项。在内核配置中，可以启用 CONFIG_NUMA 选项，它允许编译一个支持 NUMA 架构的内核。此外，还有其他一些与 NUMA 相关的配置选项，如 CONFIG_NUMA_BALANCING（NUMA 平衡）、CONFIG_NUMA_EMU（NUMA 模拟器）等。

```shell
$ grep -in numa .config
162:CONFIG_ARCH_SUPPORTS_NUMA_BALANCING=y
165:CONFIG_NUMA_BALANCING=y
166:CONFIG_NUMA_BALANCING_DEFAULT_ENABLED=y
434:CONFIG_X86_NUMACHIP=y
515:CONFIG_NUMA=y
516:CONFIG_AMD_NUMA=y
517:CONFIG_X86_64_ACPI_NUMA=y
519:# CONFIG_NUMA_EMU is not set
634:CONFIG_USE_PERCPU_NUMA_NODE_ID=y
689:CONFIG_ACPI_NUMA=y
```

### 2.3 bios控制

进入硬件bios可以选择打开NUMA。

## 3. 查看NUMA节点配置

要查看 NUMA 节点下的 CPU 核心和内存，可以使用以下方法。

### 3.1 numactl
使用 numactl 命令：numactl 是一个用于管理 NUMA 系统的实用工具。通过在命令前加上 `numactl --hardware`，可以显示当前系统中的 NUMA 节点、CPU 核心和内存的分布情况。

`numactl --hardware`

该命令将输出类似以下内容：

```
available: 4 nodes (0-3)
node 0 cpus: 0 1 2 3
node 0 size: 8192 MB
node 0 free: 4096 MB
```

其中，nodes 表示节点的数量，node x cpus 列出了节点 x 上的 CPU 核心列表，node x size 显示了节点 x 的内存总量，node x free 显示了节点 x 的可用内存。

### 3.2 /sys/devices/system/node/
查看 `/sys/devices/system/node/` 目录：Linux 内核将 NUMA 架构的信息暴露在 `/sys/devices/system/node/` 目录下。你可以使用命令行或文件浏览器来导航到该目录，并查看其中的子目录。每个子目录对应一个 NUMA 节点，其中包含有关该节点下 CPU 核心和内存的信息。

```shell
cd `/sys/devices/system/node/`
`ls -al`
```

这将显示每个 NUMA 节点的目录，例如 node0、node1 等。你可以进入这些子目录，查看其中的文件以获取与该节点相关的信息。

```shell
ls -al
total 0
drwxr-xr-x  7 root root    0 Sep 12 17:03 .
drwxr-xr-x 10 root root    0 Sep 12 17:03 ..
-r--r--r--  1 root root 4096 Sep 12 17:13 has_cpu
-r--r--r--  1 root root 4096 Sep 12 17:13 has_memory
-r--r--r--  1 root root 4096 Sep 12 17:13 has_normal_memory
drwxr-xr-x  4 root root    0 Sep 12 17:03 node0
drwxr-xr-x  3 root root    0 Sep 12 17:03 node1
drwxr-xr-x  4 root root    0 Sep 12 17:03 node2
drwxr-xr-x  3 root root    0 Sep 12 17:03 node3
-r--r--r--  1 root root 4096 Sep 12 17:13 online
-r--r--r--  1 root root 4096 Sep 12 17:13 possible
drwxr-xr-x  2 root root    0 Sep 12 17:13 power
-rw-r--r--  1 root root 4096 Sep 12 17:03 uevent
```

### 3.3 lscpu
使用 lscpu 命令：lscpu 命令可以显示有关系统 CPU 的详细信息，包括 NUMA 架构下的信息。在命令行中运行 lscpu，可以查看每个 CPU 核心所属的 NUMA 节点。

`lscpu`

输出中的 "NUMA node(s)" 列列出了每个 CPU 核心对应的 NUMA 节点。

```shell
lscpu
Architecture:          x86_64
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
CPU(s):                64
On-line CPU(s) list:   0-63
Thread(s) per core:    2
Core(s) per socket:    32
Socket(s):             1
NUMA node(s):          4
Vendor ID:             HygonGenuine
CPU family:            24
Model:                 2
Model name:            Hygon C86 7380 32-core Processor
Stepping:              2
CPU MHz:               2414.819
BogoMIPS:              4399.46
Virtualization:        AMD-V
L1d cache:             32K
L1i cache:             64K
L2 cache:              512K
L3 cache:              8192K
NUMA node0 CPU(s):     0-7,32-39
NUMA node1 CPU(s):     8-15,40-47
NUMA node2 CPU(s):     16-23,48-55
NUMA node3 CPU(s):     24-31,56-63
COPY
```

## 4 NUMA节点控制

要将内存或CPU绑定到指定的NUMA节点下，可以按照以下步骤进行操作。

### 4.1 taskset
绑定CPU到指定的NUMA节点：使用taskset命令可以将进程绑定到特定的CPU。例如，要将进程绑定到第一个NUMA节点上的CPU，可以执行以下命令：

`taskset -c 0-7 your_program`

这将把your_program进程绑定到第一个NUMA节点上的CPU核心0到7。

### 4.2 numactl

绑定内存到指定的NUMA节点：在Linux系统中，可以使用numactl命令来管理NUMA节点和内存绑定。以下是一些常用的示例命令：
将内存绑定到指定的NUMA节点：

`numactl --membind=0 your_program`

这将把your_program进程的内存绑定到第一个NUMA节点。
指定进程运行在指定的NUMA节点上：

`numactl --cpunodebind=0 --membind=0 your_program`

这将把your_program进程的CPU和内存都绑定到第一个NUMA节点。
