#ifndef __HT_UTILS_H__
#define __HT_UTILS_H__

#include <inttypes.h>
#include <rte_ether.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <rte_malloc.h>
#include <rte_timer.h> // 定时器,用来定时发送广播 arp

#include <rte_ring.h> // dpdk 队列库

#include <netinet/in.h>

// 点分十进制ipv4地址变为数字ipv4地址
#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
// 本地ip,即dpdk端口的ip(由于dpdk绕过了内核协议栈所以需要自己设置)
extern uint32_t g_local_ip;

// 六元组sip,dip,smac,dmac,sport,dport用来发送数据包,由于本项目只用于实验所以以全局变量形式
extern uint32_t g_src_ip;
extern uint32_t g_dst_ip;

extern uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
extern uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];

extern uint16_t g_src_port;
extern uint16_t g_dst_port;

extern uint8_t g_default_arp_mac[RTE_ETHER_ADDR_LEN];

#define BURST_SIZE	32
#define RING_SIZE	1024

// 两个ring队列,一个收包队列收包后存入用来解析协议
// 一个发包队列待发的包存入
// 这样做收发包可以分别通过两个不同的核心进行
struct ring_buffer {
  struct rte_ring *recv_ring;
  struct rte_ring *send_ring;
};

extern struct ring_buffer *g_ring;



/* utils */
#define rte_htons rte_cpu_to_be_16
#define rte_htonl rte_cpu_to_be_32

#define rte_ntohs rte_be_to_cpu_16
#define rte_ntohl rte_be_to_cpu_32

/* IP network to ascii representation */
const char *
inet_ntop2(uint32_t ip);

/*
 * IP network to ascii representation. To use
 * for multiple IP address convertion into the same call.
 */
char *
inet_ntoa2(uint32_t ip, char *buf);

// 链表操作
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)


#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)
/* end of utils */

#endif