#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>


#include "lpm.h"

#define MAX_LPM_RULES (256 * 1)

struct rte_lpm* lpm_table;
int is_lock = 0;

void add_lpm(char *ip_str, uint8_t mask, uint32_t  nexthop) {
	struct in_addr dst_ip;
	inet_aton(ip_str, &dst_ip);
	int ret = rte_lpm_add(lpm_table, htonl(dst_ip.s_addr), mask, nexthop);
	if(ret != 0){
		perror("rte_lpm_add");
	}else{
		printf("add %s success\n", ip_str);
	}

}

void delete_lpm(char *ip_str, uint8_t mask) {
	struct in_addr dst_ip;
	inet_aton(ip_str, &dst_ip);
	int ret = rte_lpm_delete(lpm_table, htonl(dst_ip.s_addr), mask);
	if(ret != 0){
		perror("rte_lpm_delete");
	}else{
		printf("delete %s success\n", ip_str);
	}
}

void look_up_lpm_entry(struct rte_lpm* lpm, char* dst_ip_str){
	struct in_addr dst_ip;
	uint32_t  nexthop;
	int ret;

	printf("lookup %s\n", dst_ip_str);
	inet_aton(dst_ip_str, &dst_ip);
	uint32_t ip = htonl(dst_ip.s_addr);
	ret = rte_lpm_lookup(lpm, ip, &nexthop);

	if(ret != 0){
		printf("rte_lpm_lookup error\n");
	}else{
		  printf("dst_ip:%s, nexthop:%d\n", dst_ip_str, nexthop);
	}
	return;
}

int main(int argc, char* argv[]) {
	struct rte_lpm_config config = {0};
	struct rte_lpm *lpm = NULL;

	config.max_rules = MAX_LPM_RULES;
	config.number_tbl8s = 256;

	if(argc >= 2){
		is_lock = 1;
	}

	// 创建LPM表
	lpm_table = rte_lpm_create("LPM_Table", &config);

	if (lpm_table == NULL) {
		printf("Cannot create LPM table\n");
		return -1;
	}
	// rte_lpm_dump(lpm_table);
	add_lpm("192.168.3.0", 24, 123);
	// rte_lpm_dump(lpm_table);
	add_lpm("192.168.3.44", 32, 456);
	// add_lpm("192.168.4.0", 24, 789);
	// add_lpm("192.168.4.44", 32, 101112);
	// // rte_lpm_dump(lpm_table);
	add_lpm("192.168.0.0", 16, 789);
	rte_lpm_dump(lpm_table);
	// look_up_lpm_entry(lpm_table, "192.168.3.0");
	// look_up_lpm_entry(lpm_table, "192.168.3.44");
	// look_up_lpm_entry(lpm_table, "192.168.0.0");
	// look_up_lpm_entry(lpm_table, "192.0.3.5");
	// look_up_lpm_entry(lpm_table, "192.1.3.5");
	// look_up_lpm_entry(lpm_table, "192.2.3.5");
	delete_lpm("192.168.0.0", 16);
	delete_lpm("192.168.3.44", 32);
	rte_lpm_dump(lpm_table);
	return 0;
}

