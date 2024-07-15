#ifndef __HT_SOCK_H__
#define __HT_SOCK_H__

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#include "udp.h"
#include "ht_utils.h"

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol);
// 1.通过socket id找到hostinfo 2. 设置相应的ip地址
int nbind(int sockfd, const struct sockaddr *addr,
            __attribute__((unused))  socklen_t addrlen);

ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                    struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen);


// 1. 准备一个payload结构 2.放入到send buffer中
ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                  const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen);
// 关闭socket
int nclose(int fd);

#endif