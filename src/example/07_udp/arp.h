#ifndef __HT_ARP_H__
#define __HT_ARP_H__

#include <rte_ether.h>
#include "ht_utils.h"

#include "list.h"

#define ARP_ENTRY_STATUS_DYNAMIC    0
#define ARP_ENTRY_STATUS_STATIC     1

// arp lists
extern struct list_head arp_table; // arp table的初始化,其实arp_table是头结点。
extern int arp_count; // 记录表中的arp entry个数
// arp表中实例结构,通过指针链成双向链表。整个链表即为arp表
typedef struct arp_entry_t {
  uint32_t ip;                          // ip地址
  uint8_t hw_addr[RTE_ETHER_ADDR_LEN];  // mac地址

  uint8_t type;                         // 类型(动态还是静态)

  // 缺少index字段，为了简单去掉

  struct list_head entry; // 前驱 next, 后继是 prev.都在此结构中
}arp_entry;

/* arp组包发包相关模块 */
// 构建arp response包. 自定义opcode 1为request,2为response
int ht_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);

// 发送arp response
struct rte_mbuf *ht_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);
/* end of arp */

// 查表操作,获取发送arp replay的对端的mac地址
uint8_t* ht_get_dst_macaddr(uint32_t dip);

#endif