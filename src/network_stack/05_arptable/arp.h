// arp表的实现文件
#ifndef __NG_ARP_H__
#define __NG_ARP_H__

#include <rte_ether.h>


#define ARP_ENTRY_STATUS_DYNAMIC	0
#define ARP_ENTRY_STATUS_STATIC		1

// 宏,链表添加,头插法
#define LL_ADD(item, list) do {		\
	item->prev = NULL;				\
	item->next = list;				\
	if (list != NULL) list->prev = item; \
	list = item;					\
} while(0)

// 链表中元素移除
#define LL_REMOVE(item, list) do {		\
	if (item->prev != NULL) item->prev->next = item->next;	\
	if (item->next != NULL) item->next->prev = item->prev;	\
	if (list == item) list = item->next;	\
	item->prev = item->next = NULL;			\
} while(0)

// arp表中实例结构,双向链表作为arp表
struct arp_entry {

	uint32_t ip;						// ip地址
	uint8_t hwaddr[RTE_ETHER_ADDR_LEN]; // mac地址

	uint8_t type;						// 类型(动态还是静态)
	// 这里目前缺少一个字段

	struct arp_entry *next;				// 后继
	struct arp_entry *prev;				// 前驱
	
};
// arp表结构
struct arp_table {

	struct arp_entry *entries;			//
	int count;							// 多少条arp数据

};


// 单例模式,arp表唯一
static struct  arp_table *arpt = NULL;
// arp table的初始化
static struct  arp_table *arp_table_instance(void) {

	if (arpt == NULL) {

		arpt = rte_malloc("arp table", sizeof(struct  arp_table), 0);
		if (arpt == NULL) {
			rte_exit(EXIT_FAILURE, "rte_malloc arp table failed\n");
		}
		memset(arpt, 0, sizeof(struct  arp_table));
	}

	return arpt;

}

// 查表操作,获取发送arp replay的对端的mac地址
static uint8_t* ng_get_dst_macaddr(uint32_t dip) {

	struct arp_entry *iter;
	struct arp_table *table = arp_table_instance();

	for (iter = table->entries;iter != NULL;iter = iter->next) {
		if (dip == iter->ip) { // 如果dip等于表中ip则查找到了
			return iter->hwaddr;
		}
	}

	return NULL;
}


#endif


