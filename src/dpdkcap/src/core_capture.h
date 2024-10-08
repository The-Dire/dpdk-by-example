#ifndef DPDKCAP_CORE_CAPTURE_H
#define DPDKCAP_CORE_CAPTURE_H

#include <stdint.h>

#define DPDKCAP_CAPTURE_BURST_SIZE 256

/* Core configuration structures */
struct core_capture_config {
  struct rte_ring * ring;               // 获取包的ring,将dpdk抓到的包放入到里面
  bool volatile * stop_condition;       // 停止运行标志位
  struct core_capture_stats * stats;    // 统计抓包核心的状态
  uint8_t port;                         // 
  uint8_t queue;                        // 
};

/* Statistics structure */
struct core_capture_stats {
  int core_id;      // dpdk端口的id
  uint64_t packets; //Packets successfully enqueued 包入队个数统计
  uint64_t missed_packets; //Packets core could not enqueue 丢包个数统计
};

/* Launches a capture task */
int capture_core(const struct core_capture_config * config);

#endif
