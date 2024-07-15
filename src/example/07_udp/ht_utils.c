#include "ht_utils.h"

uint32_t g_local_ip = MAKE_IPV4_ADDR(10, 66 ,24, 68);

// 六元组sip,dip,smac,dmac,sport,dport用来发送数据包,由于本项目只用于实验所以以全局变量形式
uint32_t g_src_ip;
uint32_t g_dst_ip;

uint8_t g_src_mac[RTE_ETHER_ADDR_LEN];
uint8_t g_dst_mac[RTE_ETHER_ADDR_LEN];

uint16_t g_src_port;
uint16_t g_dst_port;

uint8_t g_default_arp_mac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

/* IP network to ascii representation */
const char *
inet_ntop2(uint32_t ip)
{
  static char buf[16];
  const unsigned char *bytep;

  bytep = (const unsigned char *)&ip;
  sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
  return buf;
}

/*
 * IP network to ascii representation. To use
 * for multiple IP address convertion into the same call.
 */
char *
inet_ntoa2(uint32_t ip, char *buf)
{
  const unsigned char *bytep;

  bytep = (const unsigned char *)&ip;
  sprintf(buf, "%d.%d.%d.%d", bytep[0], bytep[1], bytep[2], bytep[3]);
  return buf;
}