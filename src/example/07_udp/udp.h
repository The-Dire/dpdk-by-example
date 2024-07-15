#ifndef __NETSTACK_UDP_H__
#define __NETSTACK_UDP_H__

#include "ht_utils.h"

#include <stdio.h>

// udp socket管理结构体
struct udp_sock_fd {
  int fd; // socket fd
  //unsigned int status; //
  uint32_t localip; // ip --> mac
  uint8_t localmac[RTE_ETHER_ADDR_LEN]; // 源mac地址,与ip地址要一一对应
  uint16_t localport;

  uint8_t protocol;

  struct rte_ring *sndbuf; // sendbuffer
  struct rte_ring *rcvbuf; // recvbuffer
  // 如果启动多个udp server,需要链表记录
  struct udp_sock_fd *prev;
  struct udp_sock_fd *next;

  pthread_cond_t cond;
  pthread_mutex_t mutex;
};

// 因为arp协议存在知道ip就能查到对应的mac,所以该结构体没有mac字段
// udp实际要发送信息结构体
struct udp_payload { // 用来组装udp数据包,理解为udp流(连接)
  uint32_t sip; // 源ip
  uint32_t dip; // 目的ip

  uint16_t sport; // 源端口
  uint16_t dport; // 目的端口

  int protocol;	// 协议

  unsigned char *data; // 数据段
  uint16_t length;	 // 长度
}; 


extern struct udp_sock_fd *g_lhost;

#define DEFAULT_FD_NUM	3
// 生成fd
int get_fd_frombitmap(void);

// 通过socket id找到对应的localhost结构体
struct udp_sock_fd * get_hostinfo_fromfd(int sockfd);

// 通过ip和post找到对应socket去接收或者发送数据包
struct udp_sock_fd * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto);

// 协议栈中udp处理流程
int ht_udp_process(struct rte_mbuf *udp_mbuf);
int ht_udp_out(struct rte_mempool *mbuf_pool);

#endif