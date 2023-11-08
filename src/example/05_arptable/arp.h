#ifndef __HT_ARP_H__
#define __HT_ARP_H__

#include <rte_ether.h>

#include "list.h"

#define ARP_ENTRY_STATUS_DYNAMIC    0
#define ARP_ENTRY_STATUS_STATIC     1

// arp lists
LIST_HEAD(arp_table); // arp table的初始化,其实arp_table是头结点。
int arp_count = 0; // 记录表中的arp entry个数
// arp表中实例结构,通过指针链成双向链表最为arp表
typedef struct arp_entry_t {
  uint32_t ip;                          // ip地址
  uint8_t hw_addr[RTE_ETHER_ADDR_LEN];  // mac地址

  uint8_t type;                         // 类型(动态还是静态)

  // 缺少index字段，为了简单去掉

  struct list_head entry; // 前驱 next, 后继是 prev.都在此结构中
}arp_entry;

// 查表操作,获取发送arp replay的对端的mac地址
uint8_t* ht_get_dst_macaddr(uint32_t dip) {
  struct list_head *cursor;
  list_for_each(cursor, &arp_table) {
    arp_entry *tmp = list_entry(cursor, arp_entry, entry);
    if (dip == tmp->ip) { // dip在表中被查到则找到了
      return tmp->hw_addr;
    }
  }
  return NULL;
}

#endif