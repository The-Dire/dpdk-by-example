# 实现arp request和arp response

上一章中实现的udp服务器需要手工配置dpdk绑定网卡的mac地址到对端主机上面。这显然不合理，如果这个udp服务器要接收上千台服务器，那么就要手工配置上千台服务器了。

此时，我们需要一种协议让我们把这个udp服务器绑定的网卡的mac地址自动告知所有想访问此服务的主机。

arp协议就应运而生了。上面这段话基本囊括了所有网络协议的诞生。比如路由协议是装载了该协议的路由器用来修改(自动添加，修改，删除)各自的路由表的协议。

本文主要做两件事:

1. 实现arp response
2. 实现icmp协议发送

两者实现了，就能够不用手动添加mac地址了。

本章 [完整代码](../../src/example/03_arp/arp.c)。本章代码是上一章更改而来，所做的更改如左 [diff](../../src/example/03_arp/arp.patch)。

## 代码分析

### arp response实现分析

上一章学会了怎么封装udp的包。其实arp也是类似的。

1. 获取网卡mac地址，放到g_src_mac中
2. 判断对端发送的是arp协议，进行arp解析。由于arp request是广播，该包的判断目标地址是否与本机ip地址相同。相同才返回arp response。(如果都返回就是arp攻击了)
3. 组装arp包
4. 使用dpdk的TX队列将包发送出去。

### 主体流程添加

添加本地ip地址,当别的主机ping 10.66.24.68的时候才会返回arp response。

```c
// 点分十进制ipv4地址变为数字ipv4地址
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
// 本地ip,即dpdk端口的ip(由于dpdk绕过了内核协议栈所以需要自己设置)
static uint32_t g_local_ip = MAKE_IPV4_ADDR(10, 66 ,24, 68);
```

在main函数添加arp处理流程:

```c
int main()
{
    ...
    // 获取网卡mac地址,用于ng_encode_udp_pkt函数中组建ether头
    rte_eth_macaddr_get(g_dpdk_port_id, (struct rte_ether_addr *)g_src_mac);
    // 包处理
    while (1) {
        
    }

}
```