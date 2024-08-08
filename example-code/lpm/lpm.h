#ifndef _LPM_H_
#define _LPM_H_


#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

#define MAX_DEPTH_TBL24 24

/** Max number of characters in LPM name. */
#define RTE_LPM_NAMESIZE                32

/** Maximum depth value possible for IPv4 LPM. */
#define RTE_LPM_MAX_DEPTH               32

/** @internal Total number of tbl24 entries. */
#define RTE_LPM_TBL24_NUM_ENTRIES       (1 << 24)

/** @internal Number of entries in a tbl8 group. */
#define RTE_LPM_TBL8_GROUP_NUM_ENTRIES  256

/** @internal Max number of tbl8 groups in the tbl8. */
#define RTE_LPM_MAX_TBL8_NUM_GROUPS         (1 << 24)

/** @internal Total number of tbl8 groups in the tbl8. */
#define RTE_LPM_TBL8_NUM_GROUPS         256

/** @internal Total number of tbl8 entries. */
#define RTE_LPM_TBL8_NUM_ENTRIES        (RTE_LPM_TBL8_NUM_GROUPS * \
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES)

#define VERIFY_DEPTH(depth) do {                                \
	if ((depth == 0) || (depth > RTE_LPM_MAX_DEPTH)){        \
		printf("LPM: Invalid depth (%u) at line %d", \
				(unsigned)(depth), __LINE__);   \
		exit(-1);} \
} while (0)

#ifndef container_of
#define container_of(ptr, type, member)	__extension__ ({		\
			const typeof(((type *)0)->member) *_ptr = (ptr); \
			 type *_target_ptr =	\
				(type *)(ptr);				\
			(type *)(((uintptr_t)_ptr) - offsetof(type, member)); \
		})
#endif

/** @internal bitmask with valid and valid_group fields set */
#define RTE_LPM_VALID_EXT_ENTRY_BITMASK 0x03000000


/** Bitmask used to indicate successful lookup */
#define RTE_LPM_LOOKUP_SUCCESS          0x01000000

enum valid_flag {
	INVALID = 0,
	VALID
};

/** LPM configuration structure. */
struct rte_lpm_config {
	uint32_t max_rules;      /**< Max number of rules. */ // 最大规则数
	uint32_t number_tbl8s;   /**< Number of tbl8s to allocate. */ // tbl8的数量
	int flags;               /**< This field is currently unused. */
};


struct rte_lpm_tbl_entry {
	/**
	 * Stores Next hop (tbl8 or tbl24 when valid_group is not set) or
	 * a group index pointing to a tbl8 structure (tbl24 only, when
	 * valid_group is set)
	 */
	uint32_t next_hop    :24;
	/* Using single uint8_t to store 3 values. */
	uint32_t valid       :1;   /**< Validation flag. */
	/**
	 * For tbl24:
	 *  - valid_group == 0: entry stores a next hop
	 *  - valid_group == 1: entry stores a group_index pointing to a tbl8
	 * For tbl8:
	 *  - valid_group indicates whether the current tbl8 is in use or not
	 */
	uint32_t valid_group :1;
	uint32_t depth       :6; /**< Rule depth. */
};

/** @internal LPM structure. */
struct rte_lpm {
	/* LPM Tables. */
	struct rte_lpm_tbl_entry tbl24[RTE_LPM_TBL24_NUM_ENTRIES];
	struct rte_lpm_tbl_entry *tbl8; /**< LPM tbl8 table. */
};

/** @internal Rule structure. */
struct rte_lpm_rule {
	uint32_t ip; /**< Rule IP address. */
	uint32_t next_hop; /**< Rule next hop. */
};

/** @internal Contains metadata about the rules table. */
struct rte_lpm_rule_info {
	uint32_t used_rules; /**< Used rules so far. */
	uint32_t first_rule; /**< Indexes the first rule of a given depth. */
};

/** @internal LPM structure. */
struct __rte_lpm {
	/* Exposed LPM data. */
	struct rte_lpm lpm;

	/* LPM metadata. */
	char name[RTE_LPM_NAMESIZE];        /**< Name of the lpm. */
	uint32_t max_rules; /**< Max. balanced rules per lpm. */
	uint32_t number_tbl8s; /**< Number of tbl8s. */
	/**< Rule info table. */
	struct rte_lpm_rule_info rule_info[RTE_LPM_MAX_DEPTH];
	struct rte_lpm_rule *rules_tbl; /**< LPM rules. */
};
// 创建lpm表
struct rte_lpm *rte_lpm_create(const char *name, const struct rte_lpm_config *config);
// 添加ip/掩码到lpm表中并标明其下一跳
int rte_lpm_add(struct rte_lpm *lpm, uint32_t ip, uint8_t depth,
		uint32_t next_hop);
// 根据ip查找lpm表
int rte_lpm_lookup(struct rte_lpm *lpm, uint32_t ip, uint32_t *next_hop);
// 从lpm表中删除对应的表项
int rte_lpm_delete(struct rte_lpm *lpm, uint32_t ip, uint8_t depth);
// 输出lpm表的各项值
void rte_lpm_dump(struct rte_lpm *lpm);

#endif

