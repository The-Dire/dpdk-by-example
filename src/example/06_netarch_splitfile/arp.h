#ifndef __HT_ARP_H__
#define __HT_ARP_H__

#include "common.h"
#include "list.h"

#define ARP_ENTRY_STATUS_DYNAMIC    0
#define ARP_ENTRY_STATUS_STATIC     1

// arp lists
LIST_HEAD(arp_table); // arp table的初始化,其实arp_table是头结点。
int arp_count = 0; // 记录表中的arp entry个数
// arp表中实例结构,通过指针链成双向链表。整个链表即为arp表
typedef struct arp_entry_t {
  uint32_t ip;                          // ip地址
  uint8_t hw_addr[RTE_ETHER_ADDR_LEN];  // mac地址

  uint8_t type;                         // 类型(动态还是静态)

  // 缺少index字段，为了简单去掉

  struct list_head entry; // 前驱 next, 后继是 prev.都在此结构中
}arp_entry;



int ht_arp_in(struct rte_mbuf *arp_mbuf);


#endif