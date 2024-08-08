
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <time.h>
#include <arpa/inet.h>

#include "lpm.h"


static uint32_t depth_to_mask(uint8_t depth)
{
	VERIFY_DEPTH(depth);
	return (int)0x80000000 >> (depth - 1);
}


static uint32_t depth_to_range(uint8_t depth)
{
	VERIFY_DEPTH(depth);

	if (depth <= MAX_DEPTH_TBL24)
		return 1 << (MAX_DEPTH_TBL24 - depth);

	/* Else if depth is greater than 24 */ // 升读大于24,还需要查tbl8
	return 1 << (RTE_LPM_MAX_DEPTH - depth);
}


/*
 * Allocates memory for LPM object
 */
struct rte_lpm *
rte_lpm_create(const char *name, const struct rte_lpm_config *config)
{
	char mem_name[RTE_LPM_NAMESIZE];
	struct __rte_lpm *i_lpm;
	struct rte_lpm *lpm = NULL;
	uint32_t mem_size, rules_size, tbl8s_size;
	struct rte_lpm_list *lpm_list;

	/* Check user arguments. */ // 检查配置
	if ((name == NULL) || (config->max_rules == 0)
			|| config->number_tbl8s > RTE_LPM_MAX_TBL8_NUM_GROUPS) {
		errno = EINVAL;
		return NULL;
	}

	snprintf(mem_name, sizeof(mem_name), "LPM_%s", name);

	/* Determine the amount of memory to allocate. */ // 计算lpm表所需空间，直接分配(dpdk中非常多提前分配的操作)
	mem_size = sizeof(*i_lpm);
	rules_size = sizeof(struct rte_lpm_rule) * config->max_rules;
	tbl8s_size = sizeof(struct rte_lpm_tbl_entry) *
			RTE_LPM_TBL8_GROUP_NUM_ENTRIES * config->number_tbl8s;

	/* Allocate memory to store the LPM data structures. */
	i_lpm = malloc(mem_size);
	if (i_lpm == NULL) {
		printf("LPM memory allocation failed\n");
		errno = ENOMEM;
		goto exit;
	}

	i_lpm->rules_tbl = malloc((size_t)rules_size);

	if (i_lpm->rules_tbl == NULL) {
		printf("LPM rules_tbl memory allocation failed\n");
		free(i_lpm);
		i_lpm = NULL;
		errno = ENOMEM;
		goto exit;
	}

	i_lpm->lpm.tbl8 = malloc((size_t)tbl8s_size);

	if (i_lpm->lpm.tbl8 == NULL) {
		printf("LPM tbl8 memory allocation failed\n");
		free(i_lpm->rules_tbl);
		free(i_lpm);
		i_lpm = NULL;
		errno = ENOMEM;
		goto exit;
	}

	/* Save user arguments. */
	i_lpm->max_rules = config->max_rules;
	i_lpm->number_tbl8s = config->number_tbl8s;
	strncpy(i_lpm->name, name, sizeof(i_lpm->name));

	lpm = &i_lpm->lpm;

exit:
	return lpm;
}


/*
 * Adds a rule to the rule table.
 *
 * NOTE: The rule table is split into 32 groups. Each group contains rules that
 * apply to a specific prefix depth (i.e. group 1 contains rules that apply to
 * prefixes with a depth of 1 etc.). In the following code (depth - 1) is used
 * to refer to depth 1 because even though the depth range is 1 - 32, depths
 * are stored in the rule table from 0 - 31.
 * NOTE: Valid range for depth parameter is 1 .. 32 inclusive.
 */
static int32_t
rule_add(struct __rte_lpm *i_lpm, uint32_t ip_masked, uint8_t depth,
	uint32_t next_hop)
{
	uint32_t rule_gindex, rule_index, last_rule;
	int i;

	VERIFY_DEPTH(depth);

	/* Scan through rule group to see if rule already exists. */
	if (i_lpm->rule_info[depth - 1].used_rules > 0) {

		/* rule_gindex stands for rule group index. */
		rule_gindex = i_lpm->rule_info[depth - 1].first_rule;
		/* Initialise rule_index to point to start of rule group. */
		rule_index = rule_gindex;
		/* Last rule = Last used rule in this rule group. */
		last_rule = rule_gindex + i_lpm->rule_info[depth - 1].used_rules;

		for (; rule_index < last_rule; rule_index++) {

			/* If rule already exists update next hop and return. */
			if (i_lpm->rules_tbl[rule_index].ip == ip_masked) {

				if (i_lpm->rules_tbl[rule_index].next_hop
						== next_hop)
					return -EEXIST;
				i_lpm->rules_tbl[rule_index].next_hop = next_hop;

				return rule_index;
			}
		}

		if (rule_index == i_lpm->max_rules)
			return -ENOSPC;
	} else {
		/* Calculate the position in which the rule will be stored. */
		rule_index = 0;

		for (i = depth - 1; i > 0; i--) {
			if (i_lpm->rule_info[i - 1].used_rules > 0) {
				rule_index = i_lpm->rule_info[i - 1].first_rule
						+ i_lpm->rule_info[i - 1].used_rules;
				break;
			}
		}
		if (rule_index == i_lpm->max_rules)
			return -ENOSPC;

		i_lpm->rule_info[depth - 1].first_rule = rule_index;
	}

	/* Make room for the new rule in the array. */
	for (i = RTE_LPM_MAX_DEPTH; i > depth; i--) {
		if (i_lpm->rule_info[i - 1].first_rule
				+ i_lpm->rule_info[i - 1].used_rules == i_lpm->max_rules)
			return -ENOSPC;

		if (i_lpm->rule_info[i - 1].used_rules > 0) {
			i_lpm->rules_tbl[i_lpm->rule_info[i - 1].first_rule
				+ i_lpm->rule_info[i - 1].used_rules]
					= i_lpm->rules_tbl[i_lpm->rule_info[i - 1].first_rule];
			i_lpm->rule_info[i - 1].first_rule++;
		}
	}

	/* Add the new rule. */
	i_lpm->rules_tbl[rule_index].ip = ip_masked;
	i_lpm->rules_tbl[rule_index].next_hop = next_hop;

	/* Increment the used rules counter for this rule group. */
	i_lpm->rule_info[depth - 1].used_rules++;

	return rule_index;
}


static int32_t add_depth_small(struct __rte_lpm *i_lpm, uint32_t ip, uint8_t depth,
		uint32_t next_hop)
{
#define group_idx next_hop
	uint32_t tbl24_index, tbl24_range, tbl8_index, tbl8_group_end, i, j;

	/* Calculate the index into Table24. */
	tbl24_index = ip >> 8;
	tbl24_range = depth_to_range(depth);

	for (i = tbl24_index; i < (tbl24_index + tbl24_range); i++) {
		/*
		 * For invalid OR valid and non-extended tbl 24 entries set
		 * entry.
		 */
		if (!i_lpm->lpm.tbl24[i].valid || (i_lpm->lpm.tbl24[i].valid_group == 0 &&
				i_lpm->lpm.tbl24[i].depth <= depth)) {

			struct rte_lpm_tbl_entry new_tbl24_entry = {
				.next_hop = next_hop,
				.valid = VALID,
				.valid_group = 0,
				.depth = depth,
			};

			/* Setting tbl24 entry in one go to avoid race
			 * conditions
			 */
			__atomic_store(&i_lpm->lpm.tbl24[i], &new_tbl24_entry,
					__ATOMIC_RELEASE);

			continue;
		}

		if (i_lpm->lpm.tbl24[i].valid_group == 1) {
			/* If tbl24 entry is valid and extended calculate the
			 *  index into tbl8.
			 */
			tbl8_index = i_lpm->lpm.tbl24[i].group_idx *
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES;
			tbl8_group_end = tbl8_index +
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES;

			for (j = tbl8_index; j < tbl8_group_end; j++) {
				if (!i_lpm->lpm.tbl8[j].valid ||
						i_lpm->lpm.tbl8[j].depth <= depth) {
					struct rte_lpm_tbl_entry
						new_tbl8_entry = {
						.valid = VALID,
						.valid_group = VALID,
						.depth = depth,
						.next_hop = next_hop,
					};

					/*
					 * Setting tbl8 entry in one go to avoid
					 * race conditions
					 */
					__atomic_store(&i_lpm->lpm.tbl8[j],
						&new_tbl8_entry,
						__ATOMIC_RELAXED);

					continue;
				}
			}
		}
	}
#undef group_idx
	return 0;
}

/*
 * Find, clean and allocate a tbl8.
 */
static int32_t
_tbl8_alloc(struct __rte_lpm *i_lpm)
{
	uint32_t group_idx; /* tbl8 group index. */
	struct rte_lpm_tbl_entry *tbl8_entry;

	/* Scan through tbl8 to find a free (i.e. INVALID) tbl8 group. */
	for (group_idx = 0; group_idx < i_lpm->number_tbl8s * RTE_LPM_TBL8_GROUP_NUM_ENTRIES; group_idx++) {
		tbl8_entry = &i_lpm->lpm.tbl8[group_idx *
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES];
		/* If a free tbl8 group is found clean it and set as VALID. */
		if (!tbl8_entry->valid_group) {
			struct rte_lpm_tbl_entry new_tbl8_entry = {
				.next_hop = 0,
				.valid = INVALID,
				.depth = 0,
				.valid_group = VALID,
			};

			memset(&tbl8_entry[0], 0,
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES *
					sizeof(tbl8_entry[0]));

			__atomic_store(tbl8_entry, &new_tbl8_entry,
					__ATOMIC_RELAXED);

			/* Return group index for allocated tbl8 group. */
			return group_idx;
		}
	}

	/* If there are no tbl8 groups free then return error. */
	return -ENOSPC;
}

static int32_t
tbl8_alloc(struct __rte_lpm *i_lpm)
{
	int32_t group_idx; /* tbl8 group index. */

	group_idx = _tbl8_alloc(i_lpm);

	return group_idx;
}


static  int32_t
add_depth_big(struct __rte_lpm *i_lpm, uint32_t ip_masked, uint8_t depth,
		uint32_t next_hop)
{
#define group_idx next_hop
	uint32_t tbl24_index;
	int32_t tbl8_group_index, tbl8_group_start, tbl8_group_end, tbl8_index,
		tbl8_range, i;

	tbl24_index = (ip_masked >> 8);
	tbl8_range = depth_to_range(depth);

	if (!i_lpm->lpm.tbl24[tbl24_index].valid) {
		/* Search for a free tbl8 group. */
		tbl8_group_index = tbl8_alloc(i_lpm);

		/* Check tbl8 allocation was successful. */
		if (tbl8_group_index < 0) {
			return tbl8_group_index;
		}

		/* Find index into tbl8 and range. */
		tbl8_index = (tbl8_group_index *
				RTE_LPM_TBL8_GROUP_NUM_ENTRIES) +
				(ip_masked & 0xFF);

		/* Set tbl8 entry. */
		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {
			struct rte_lpm_tbl_entry new_tbl8_entry = {
				.valid = VALID,
				.depth = depth,
				.valid_group = i_lpm->lpm.tbl8[i].valid_group,
				.next_hop = next_hop,
			};
			__atomic_store(&i_lpm->lpm.tbl8[i], &new_tbl8_entry,
					__ATOMIC_RELAXED);
		}

		/*
		 * Update tbl24 entry to point to new tbl8 entry. Note: The
		 * ext_flag and tbl8_index need to be updated simultaneously,
		 * so assign whole structure in one go
		 */

		struct rte_lpm_tbl_entry new_tbl24_entry = {
			.group_idx = tbl8_group_index,
			.valid = VALID,
			.valid_group = 1,
			.depth = 0,
		};

		/* The tbl24 entry must be written only after the
		 * tbl8 entries are written.
		 */
		__atomic_store(&i_lpm->lpm.tbl24[tbl24_index], &new_tbl24_entry,
				__ATOMIC_RELEASE);

	} /* If valid entry but not extended calculate the index into Table8. */
	else if (i_lpm->lpm.tbl24[tbl24_index].valid_group == 0) {
		/* Search for free tbl8 group. */
		tbl8_group_index = tbl8_alloc(i_lpm);

		if (tbl8_group_index < 0) {
			return tbl8_group_index;
		}

		tbl8_group_start = tbl8_group_index *
				RTE_LPM_TBL8_GROUP_NUM_ENTRIES;
		tbl8_group_end = tbl8_group_start +
				RTE_LPM_TBL8_GROUP_NUM_ENTRIES;

		/* Populate new tbl8 with tbl24 value. */
		for (i = tbl8_group_start; i < tbl8_group_end; i++) {
			struct rte_lpm_tbl_entry new_tbl8_entry = {
				.valid = VALID,
				.depth = i_lpm->lpm.tbl24[tbl24_index].depth,
				.valid_group = i_lpm->lpm.tbl8[i].valid_group,
				.next_hop = i_lpm->lpm.tbl24[tbl24_index].next_hop,
			};
			__atomic_store(&i_lpm->lpm.tbl8[i], &new_tbl8_entry,
					__ATOMIC_RELAXED);
		}

		tbl8_index = tbl8_group_start + (ip_masked & 0xFF);

		/* Insert new rule into the tbl8 entry. */
		for (i = tbl8_index; i < tbl8_index + tbl8_range; i++) {
			struct rte_lpm_tbl_entry new_tbl8_entry = {
				.valid = VALID,
				.depth = depth,
				.valid_group = i_lpm->lpm.tbl8[i].valid_group,
				.next_hop = next_hop,
			};
			__atomic_store(&i_lpm->lpm.tbl8[i], &new_tbl8_entry,
					__ATOMIC_RELAXED);
		}

		/*
		 * Update tbl24 entry to point to new tbl8 entry. Note: The
		 * ext_flag and tbl8_index need to be updated simultaneously,
		 * so assign whole structure in one go.
		 */

		struct rte_lpm_tbl_entry new_tbl24_entry = {
				.group_idx = tbl8_group_index,
				.valid = VALID,
				.valid_group = 1,
				.depth = 0,
		};

		/* The tbl24 entry must be written only after the
		 * tbl8 entries are written.
		 */
		__atomic_store(&i_lpm->lpm.tbl24[tbl24_index], &new_tbl24_entry,
				__ATOMIC_RELEASE);

	} else { /*
		* If it is valid, extended entry calculate the index into tbl8.
		*/
		tbl8_group_index = i_lpm->lpm.tbl24[tbl24_index].group_idx;
		tbl8_group_start = tbl8_group_index *
				RTE_LPM_TBL8_GROUP_NUM_ENTRIES;
		tbl8_index = tbl8_group_start + (ip_masked & 0xFF);

		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {

			if (!i_lpm->lpm.tbl8[i].valid ||
					i_lpm->lpm.tbl8[i].depth <= depth) {
				struct rte_lpm_tbl_entry new_tbl8_entry = {
					.valid = VALID,
					.depth = depth,
					.next_hop = next_hop,
					.valid_group = i_lpm->lpm.tbl8[i].valid_group,
				};

				/*
				 * Setting tbl8 entry in one go to avoid race
				 * condition
				 */
				__atomic_store(&i_lpm->lpm.tbl8[i], &new_tbl8_entry,
						__ATOMIC_RELAXED);

				continue;
			}
		}
	}
#undef group_idx
	return 0;
}


/*
 * Delete a rule from the rule table.
 * NOTE: Valid range for depth parameter is 1 .. 32 inclusive.
 */
static void
rule_delete(struct __rte_lpm *i_lpm, int32_t rule_index, uint8_t depth)
{
	int i;

	VERIFY_DEPTH(depth);

	i_lpm->rules_tbl[rule_index] =
			i_lpm->rules_tbl[i_lpm->rule_info[depth - 1].first_rule
			+ i_lpm->rule_info[depth - 1].used_rules - 1];

	for (i = depth; i < RTE_LPM_MAX_DEPTH; i++) {
		if (i_lpm->rule_info[i].used_rules > 0) {
			i_lpm->rules_tbl[i_lpm->rule_info[i].first_rule - 1] =
					i_lpm->rules_tbl[i_lpm->rule_info[i].first_rule
						+ i_lpm->rule_info[i].used_rules - 1];
			i_lpm->rule_info[i].first_rule--;
		}
	}

	i_lpm->rule_info[depth - 1].used_rules--;
}


/*
 * Add a route
 */
int rte_lpm_add(struct rte_lpm *lpm, uint32_t ip, uint8_t depth,
		uint32_t next_hop)
{
	int32_t rule_index, status = 0;
	struct __rte_lpm *i_lpm;
	uint32_t ip_masked;

	/* Check user arguments. */
	if ((lpm == NULL) || (depth < 1) || (depth > RTE_LPM_MAX_DEPTH))
		return -EINVAL;

	i_lpm = container_of(lpm, struct __rte_lpm, lpm);
	ip_masked = ip & depth_to_mask(depth);

	/* Add the rule to the rule table. */
	rule_index = rule_add(i_lpm, ip_masked, depth, next_hop);

	/* Skip table entries update if The rule is the same as
	 * the rule in the rules table.
	 */
	if (rule_index == -EEXIST){
		printf("ip_masked:%u  have already exist!\n", ip_masked);
		return 0;
	}
	//printf("ip_masked:%u  not exist!\n", ip_masked);

	/* If the is no space available for new rule return error. */
	if (rule_index < 0) {
		return rule_index;
	}

	if (depth <= MAX_DEPTH_TBL24) {
		status = add_depth_small(i_lpm, ip_masked, depth, next_hop);
	} else { /* If depth > RTE_LPM_MAX_DEPTH_TBL24 */
		status = add_depth_big(i_lpm, ip_masked, depth, next_hop);

		/*
		 * If add fails due to exhaustion of tbl8 extensions delete
		 * rule that was added to rule table.
		 */
		if (status < 0) {
			rule_delete(i_lpm, rule_index, depth);

			return status;
		}
	}

	return 0;
}


uint32_t generateRandomIPv4() {
    uint32_t ip = 0;

    uint8_t byte1 = rand() % 256;
    uint8_t byte2 = rand() % 256;
    uint8_t byte3 = rand() % 256;
    uint8_t byte4 = rand() % 256;

    ip = (byte1 << 24) | (byte2 << 16) | (byte3 << 8) | byte4;

    return ip;
}



/**
 * Lookup an IP into the LPM table.
 *
 * @param lpm
 *   LPM object handle
 * @param ip
 *   IP to be looked up in the LPM table
 * @param next_hop
 *   Next hop of the most specific rule found for IP (valid on lookup hit only)
 * @return
 *   -EINVAL for incorrect arguments, -ENOENT on lookup miss, 0 on lookup hit
 */
int rte_lpm_lookup(struct rte_lpm *lpm, uint32_t ip, uint32_t *next_hop)
{
	unsigned tbl24_index = (ip >> 8);
	uint32_t tbl_entry;
	const uint32_t *ptbl;

	/* DEBUG: Check user input arguments. */
	if((lpm == NULL) || (next_hop == NULL))
		errno = -EINVAL;

	/* Copy tbl24 entry */
	ptbl = (const uint32_t *)(&lpm->tbl24[tbl24_index]);
	tbl_entry = *ptbl;

	/* Memory ordering is not required in lookup. Because dataflow
	 * dependency exists, compiler or HW won't be able to re-order
	 * the operations.
	 */
	/* Copy tbl8 entry (only if needed) */
	//unlikely
	if ((tbl_entry & RTE_LPM_VALID_EXT_ENTRY_BITMASK) ==
			RTE_LPM_VALID_EXT_ENTRY_BITMASK) {

		unsigned tbl8_index = (uint8_t)ip +
				(((uint32_t)tbl_entry & 0x00FFFFFF) *
						RTE_LPM_TBL8_GROUP_NUM_ENTRIES);

		ptbl = (const uint32_t *)&lpm->tbl8[tbl8_index];
		tbl_entry = *ptbl;
	}

	*next_hop = ((uint32_t)tbl_entry & 0x00FFFFFF);
	return (tbl_entry & RTE_LPM_LOOKUP_SUCCESS) ? 0 : -ENOENT;
}


/*
 * Checks if table 8 group can be recycled.
 *
 * Return of -EEXIST means tbl8 is in use and thus can not be recycled.
 * Return of -EINVAL means tbl8 is empty and thus can be recycled
 * Return of value > -1 means tbl8 is in use but has all the same values and
 * thus can be recycled
 */
static int32_t
tbl8_recycle_check(struct rte_lpm_tbl_entry *tbl8,
		uint32_t tbl8_group_start)
{
	uint32_t tbl8_group_end, i;
	tbl8_group_end = tbl8_group_start + RTE_LPM_TBL8_GROUP_NUM_ENTRIES;

	/*
	 * Check the first entry of the given tbl8. If it is invalid we know
	 * this tbl8 does not contain any rule with a depth < RTE_LPM_MAX_DEPTH
	 *  (As they would affect all entries in a tbl8) and thus this table
	 *  can not be recycled.
	 */
	if (tbl8[tbl8_group_start].valid) {
		/*
		 * If first entry is valid check if the depth is less than 24
		 * and if so check the rest of the entries to verify that they
		 * are all of this depth.
		 */
		if (tbl8[tbl8_group_start].depth <= MAX_DEPTH_TBL24) {
			for (i = (tbl8_group_start + 1); i < tbl8_group_end;
					i++) {

				if (tbl8[i].depth !=
						tbl8[tbl8_group_start].depth) {

					return -EEXIST;
				}
			}
			/* If all entries are the same return the tb8 index */
			return tbl8_group_start;
		}

		return -EEXIST;
	}
	/*
	 * If the first entry is invalid check if the rest of the entries in
	 * the tbl8 are invalid.
	 */
	for (i = (tbl8_group_start + 1); i < tbl8_group_end; i++) {
		if (tbl8[i].valid)
			return -EEXIST;
	}
	/* If no valid entries are found then return -EINVAL. */
	return -EINVAL;
}


static int32_t
tbl8_free(struct __rte_lpm *i_lpm, uint32_t tbl8_group_start)
{
	struct rte_lpm_tbl_entry zero_tbl8_entry = {0};
	int status;

/*
	if (i_lpm->v == NULL) {
		__atomic_store(&i_lpm->lpm.tbl8[tbl8_group_start], &zero_tbl8_entry,
				__ATOMIC_RELAXED);
	}
*/

	return 0;
}


static int32_t
delete_depth_big(struct __rte_lpm *i_lpm, uint32_t ip_masked,
	uint8_t depth, int32_t sub_rule_index, uint8_t sub_rule_depth)
{
#define group_idx next_hop
	uint32_t tbl24_index, tbl8_group_index, tbl8_group_start, tbl8_index,
			tbl8_range, i;
	int32_t tbl8_recycle_index, status = 0;

	/*
	 * Calculate the index into tbl24 and range. Note: All depths larger
	 * than MAX_DEPTH_TBL24 are associated with only one tbl24 entry.
	 */
	tbl24_index = ip_masked >> 8;

	/* Calculate the index into tbl8 and range. */
	tbl8_group_index = i_lpm->lpm.tbl24[tbl24_index].group_idx;
	tbl8_group_start = tbl8_group_index * RTE_LPM_TBL8_GROUP_NUM_ENTRIES;
	tbl8_index = tbl8_group_start + (ip_masked & 0xFF);
	tbl8_range = depth_to_range(depth);

	if (sub_rule_index < 0) {
		/*
		 * Loop through the range of entries on tbl8 for which the
		 * rule_to_delete must be removed or modified.
		 */
		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {
			if (i_lpm->lpm.tbl8[i].depth <= depth)
				i_lpm->lpm.tbl8[i].valid = INVALID;
		}
	} else {
		/* Set new tbl8 entry. */
		struct rte_lpm_tbl_entry new_tbl8_entry = {
			.valid = VALID,
			.depth = sub_rule_depth,
			.valid_group = i_lpm->lpm.tbl8[tbl8_group_start].valid_group,
			.next_hop = i_lpm->rules_tbl[sub_rule_index].next_hop,
		};

		/*
		 * Loop through the range of entries on tbl8 for which the
		 * rule_to_delete must be modified.
		 */
		for (i = tbl8_index; i < (tbl8_index + tbl8_range); i++) {
			if (i_lpm->lpm.tbl8[i].depth <= depth)
				__atomic_store(&i_lpm->lpm.tbl8[i], &new_tbl8_entry,
						__ATOMIC_RELAXED);
		}
	}

	/*
	 * Check if there are any valid entries in this tbl8 group. If all
	 * tbl8 entries are invalid we can free the tbl8 and invalidate the
	 * associated tbl24 entry.
	 */

	tbl8_recycle_index = tbl8_recycle_check(i_lpm->lpm.tbl8, tbl8_group_start);

	if (tbl8_recycle_index == -EINVAL) {
		/* Set tbl24 before freeing tbl8 to avoid race condition.
		 * Prevent the free of the tbl8 group from hoisting.
		 */
		i_lpm->lpm.tbl24[tbl24_index].valid = 0;
		__atomic_thread_fence(__ATOMIC_RELEASE);
		status = tbl8_free(i_lpm, tbl8_group_start);
	} else if (tbl8_recycle_index > -1) {
		/* Update tbl24 entry. */
		struct rte_lpm_tbl_entry new_tbl24_entry = {
			.next_hop = i_lpm->lpm.tbl8[tbl8_recycle_index].next_hop,
			.valid = VALID,
			.valid_group = 0,
			.depth = i_lpm->lpm.tbl8[tbl8_recycle_index].depth,
		};

		/* Set tbl24 before freeing tbl8 to avoid race condition.
		 * Prevent the free of the tbl8 group from hoisting.
		 */
		__atomic_store(&i_lpm->lpm.tbl24[tbl24_index], &new_tbl24_entry,
				__ATOMIC_RELAXED);
		__atomic_thread_fence(__ATOMIC_RELEASE);
		status = tbl8_free(i_lpm, tbl8_group_start);
	}
#undef group_idx
	return status;
}


static int32_t
delete_depth_small(struct __rte_lpm *i_lpm, uint32_t ip_masked,
	uint8_t depth, int32_t sub_rule_index, uint8_t sub_rule_depth)
{
#define group_idx next_hop
	uint32_t tbl24_range, tbl24_index, tbl8_group_index, tbl8_index, i, j;

	/* Calculate the range and index into Table24. */
	tbl24_range = depth_to_range(depth);
	tbl24_index = (ip_masked >> 8);
	struct rte_lpm_tbl_entry zero_tbl24_entry = {0};

	/*
	 * Firstly check the sub_rule_index. A -1 indicates no replacement rule
	 * and a positive number indicates a sub_rule_index.
	 */
	if (sub_rule_index < 0) {
		/*
		 * If no replacement rule exists then invalidate entries
		 * associated with this rule.
		 */
		for (i = tbl24_index; i < (tbl24_index + tbl24_range); i++) {

			if (i_lpm->lpm.tbl24[i].valid_group == 0 &&
					i_lpm->lpm.tbl24[i].depth <= depth) {
				__atomic_store(&i_lpm->lpm.tbl24[i],
					&zero_tbl24_entry, __ATOMIC_RELEASE);
			} else if (i_lpm->lpm.tbl24[i].valid_group == 1) {
				/*
				 * If TBL24 entry is extended, then there has
				 * to be a rule with depth >= 25 in the
				 * associated TBL8 group.
				 */

				tbl8_group_index = i_lpm->lpm.tbl24[i].group_idx;
				tbl8_index = tbl8_group_index *
						RTE_LPM_TBL8_GROUP_NUM_ENTRIES;

				for (j = tbl8_index; j < (tbl8_index +
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES); j++) {

					if (i_lpm->lpm.tbl8[j].depth <= depth)
						i_lpm->lpm.tbl8[j].valid = INVALID;
				}
			}
		}
	} else {
		/*
		 * If a replacement rule exists then modify entries
		 * associated with this rule.
		 */

		struct rte_lpm_tbl_entry new_tbl24_entry = {
			.next_hop = i_lpm->rules_tbl[sub_rule_index].next_hop,
			.valid = VALID,
			.valid_group = 0,
			.depth = sub_rule_depth,
		};

		struct rte_lpm_tbl_entry new_tbl8_entry = {
			.valid = VALID,
			.valid_group = VALID,
			.depth = sub_rule_depth,
			.next_hop = i_lpm->rules_tbl
			[sub_rule_index].next_hop,
		};

		for (i = tbl24_index; i < (tbl24_index + tbl24_range); i++) {

			if (i_lpm->lpm.tbl24[i].valid_group == 0 &&
					i_lpm->lpm.tbl24[i].depth <= depth) {
				__atomic_store(&i_lpm->lpm.tbl24[i], &new_tbl24_entry,
						__ATOMIC_RELEASE);
			} else  if (i_lpm->lpm.tbl24[i].valid_group == 1) {
				/*
				 * If TBL24 entry is extended, then there has
				 * to be a rule with depth >= 25 in the
				 * associated TBL8 group.
				 */

				tbl8_group_index = i_lpm->lpm.tbl24[i].group_idx;
				tbl8_index = tbl8_group_index *
						RTE_LPM_TBL8_GROUP_NUM_ENTRIES;

				for (j = tbl8_index; j < (tbl8_index +
					RTE_LPM_TBL8_GROUP_NUM_ENTRIES); j++) {

					if (i_lpm->lpm.tbl8[j].depth <= depth)
						__atomic_store(&i_lpm->lpm.tbl8[j],
							&new_tbl8_entry,
							__ATOMIC_RELAXED);
				}
			}
		}
	}
#undef group_idx
	return 0;
}



/*
 * Finds a rule in rule table.
 * NOTE: Valid range for depth parameter is 1 .. 32 inclusive.
 */
static int32_t
rule_find(struct __rte_lpm *i_lpm, uint32_t ip_masked, uint8_t depth)
{
	uint32_t rule_gindex, last_rule, rule_index;

	VERIFY_DEPTH(depth);

	rule_gindex = i_lpm->rule_info[depth - 1].first_rule;
	last_rule = rule_gindex + i_lpm->rule_info[depth - 1].used_rules;

	/* Scan used rules at given depth to find rule. */
	for (rule_index = rule_gindex; rule_index < last_rule; rule_index++) {
		/* If rule is found return the rule index. */
		if (i_lpm->rules_tbl[rule_index].ip == ip_masked)
			return rule_index;
	}

	/* If rule is not found return -EINVAL. */
	return -EINVAL;
}


static int32_t
find_previous_rule(struct __rte_lpm *i_lpm, uint32_t ip, uint8_t depth,
		uint8_t *sub_rule_depth)
{
	int32_t rule_index;
	uint32_t ip_masked;
	uint8_t prev_depth;

	for (prev_depth = (uint8_t)(depth - 1); prev_depth > 0; prev_depth--) {
		ip_masked = ip & depth_to_mask(prev_depth);

		rule_index = rule_find(i_lpm, ip_masked, prev_depth);

		if (rule_index >= 0) {
			*sub_rule_depth = prev_depth;
			return rule_index;
		}
	}

	return -1;
}



/*
 * Deletes a rule
 */
int rte_lpm_delete(struct rte_lpm *lpm, uint32_t ip, uint8_t depth)
{
	int32_t rule_to_delete_index, sub_rule_index;
	struct __rte_lpm *i_lpm;
	uint32_t ip_masked;
	uint8_t sub_rule_depth;
	/*
	 * Check input arguments. Note: IP must be a positive integer of 32
	 * bits in length therefore it need not be checked.
	 */
	if ((lpm == NULL) || (depth < 1) || (depth > RTE_LPM_MAX_DEPTH)) {
		return -EINVAL;
	}

	i_lpm = container_of(lpm, struct __rte_lpm, lpm);
	ip_masked = ip & depth_to_mask(depth);

	/*
	 * Find the index of the input rule, that needs to be deleted, in the
	 * rule table.
	 */
	rule_to_delete_index = rule_find(i_lpm, ip_masked, depth);

	/*
	 * Check if rule_to_delete_index was found. If no rule was found the
	 * function rule_find returns -EINVAL.
	 */
	if (rule_to_delete_index < 0)
		return -EINVAL;

	/* Delete the rule from the rule table. */
	rule_delete(i_lpm, rule_to_delete_index, depth);

	/*
	 * Find rule to replace the rule_to_delete. If there is no rule to
	 * replace the rule_to_delete we return -1 and invalidate the table
	 * entries associated with this rule.
	 */
	sub_rule_depth = 0;
	sub_rule_index = find_previous_rule(i_lpm, ip, depth, &sub_rule_depth);

	/*
	 * If the input depth value is less than 25 use function
	 * delete_depth_small otherwise use delete_depth_big.
	 */
	if (depth <= MAX_DEPTH_TBL24) {
		return delete_depth_small(i_lpm, ip_masked, depth,
				sub_rule_index, sub_rule_depth);
	} else { /* If depth > MAX_DEPTH_TBL24 */
		return delete_depth_big(i_lpm, ip_masked, depth, sub_rule_index,
				sub_rule_depth);
	}
}

void rte_lpm_dump(struct rte_lpm *lpm){
	struct __rte_lpm *i_lpm;
	struct rte_lpm_rule_info  *rule_info;
	int i, j;
	
	i_lpm = container_of(lpm, struct __rte_lpm, lpm);
	rule_info = i_lpm->rule_info;
	printf("lpm@%s:\n", i_lpm->name);
	printf("\nrule_info\n");
	for(i=0; i < RTE_LPM_MAX_DEPTH; i++){
		if (rule_info[i].first_rule == 0 && rule_info[i].used_rules == 0) {
			continue;
		}
		printf("\tdepth:%d, first_rule:%d, used_rules:%d\n", i + 1, rule_info[i].first_rule, rule_info[i].used_rules);
	}

	printf("\nrules_tbl\n");
	for (i = 0; i < i_lpm->max_rules; i++) {
		if (i_lpm->rules_tbl[i].ip == 0 && i_lpm->rules_tbl[i].next_hop == 0) {
			continue;
		}
		// 将整数IP转换为网络字节顺序
		struct in_addr ip_addr;
		ip_addr.s_addr = htonl(i_lpm->rules_tbl[i].ip);

		// 转换为点分十进制字符串
		char *ip_str = inet_ntoa(ip_addr);

		printf("Rule %d: IP = %s , Next Hop = %u '\n", 
			i, 
			ip_str,
			i_lpm->rules_tbl[i].next_hop);
	}
	// 打印表格头部
	printf("\ntbl24\n");
    printf("|%-9s| %-10s | %-6s | %-11s | %-5s |\n","index", "Next Hop", "Valid", "Valid Group", "Depth");
    printf("+------------+--------+-------------+-------+\n");
	for (i = 0; i < RTE_LPM_TBL24_NUM_ENTRIES; i++) {
		if (((i_lpm->lpm.tbl24)[i].next_hop)==0 && ((i_lpm->lpm.tbl24)[i].valid)==0 
		&& ((i_lpm->lpm.tbl24)[i].valid_group)==0 
		&& ((i_lpm->lpm.tbl24)[i].depth)==0)
			continue;
		printf("|%-9d| %-10u | %-6u | %-11u | %-5u |\n",
           i, ( i_lpm->lpm.tbl24)[i].next_hop, (i_lpm->lpm.tbl24)[i].valid, (i_lpm->lpm.tbl24)[i].valid_group, (i_lpm->lpm.tbl24)[i].depth);
	}


	// 打印表格头部
	printf("\ntbl8\n");
    printf("|%-9s| %-10s | %-6s | %-11s | %-5s |\n","index", "Next Hop", "Valid", "Valid Group", "Depth");
    printf("+------------+--------+-------------+-------+\n");
	for (i = 0; i < i_lpm->number_tbl8s; i++) {
		printf("tbl8 index = %d.\n", i);
		for (j = 0; j < RTE_LPM_TBL8_GROUP_NUM_ENTRIES; j++) {
			int index = i * RTE_LPM_TBL8_GROUP_NUM_ENTRIES + j;
			struct rte_lpm_tbl_entry *entry = &i_lpm->lpm.tbl8[i * RTE_LPM_TBL8_GROUP_NUM_ENTRIES + j];

			if (((i_lpm->lpm.tbl8)[index].next_hop)==0 && ((i_lpm->lpm.tbl8)[index].valid)==0 
				&& ((i_lpm->lpm.tbl8)[index].valid_group)==0 
				&& ((i_lpm->lpm.tbl8)[index].depth)==0)
					continue;
			printf("|%-9d| %-10u | %-6u | %-11u | %-5u |\n",
				j, ( i_lpm->lpm.tbl8)[index].next_hop, (i_lpm->lpm.tbl8)[index].valid, (i_lpm->lpm.tbl8)[index].valid_group, (i_lpm->lpm.tbl8)[index].depth);
		}
		
	}
	return;
}
