#include "sock.h"

int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {
  int fd = get_fd_frombitmap(); // 1.文件描述符fd生成
  // 2.分配一个host
  struct udp_sock_fd *host = rte_malloc("udp_socket", sizeof(struct udp_sock_fd), 0);
  if (host == NULL) {
    return -1;
  }
  memset(host, 0, sizeof(struct udp_sock_fd));
  // 文件描述符赋值
  host->fd = fd;
  // 通过type赋值要传输的协议
  if (type == SOCK_DGRAM)
    host->protocol = IPPROTO_UDP;
  /*
  else if (type == SOCK_STREAM) // tcp socket待实现
      host->protocol = IPPROTO_TCP;
  */

  // 构建recv buffer和send buffer
  host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
  if (host->rcvbuf == NULL) {
    rte_free(host);
    return -1;
  }

  host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
  if (host->sndbuf == NULL) {
    rte_ring_free(host->rcvbuf);
    rte_free(host);
    return -1;
  }
  // 用于实现阻塞,在recvfrom里面调用
  pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
  rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

  pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
  rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));
  // 3.该host(socket)添加到socket链表中
  LL_ADD(host, g_lhost);

  return fd;
}
// 1.通过socket id找到hostinfo 2. 设置相应的ip地址
int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

  struct udp_sock_fd *host =  get_hostinfo_fromfd(sockfd);
  if (host == NULL) return -1;

  const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
  host->localport = laddr->sin_port;
  rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
  rte_memcpy(host->localmac, g_src_mac, RTE_ETHER_ADDR_LEN);

  return 0;
}

ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                  struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {
  // 1.判断host是否存在
  struct udp_sock_fd *host =  get_hostinfo_fromfd(sockfd);
  if (host == NULL) {
    printf("host not exist\n");
    return -1;
  }

  struct udp_payload *payload = NULL;
  unsigned char *ptr = NULL;

  struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
  int nb = -1;
  // 2.阻塞等待地接收数据
  // 加入来锁为阻塞地接收数据
  pthread_mutex_lock(&host->mutex);
  // recv buffer里面接收一个数据包(把buffer里面的值放入到ol中)
  while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&payload)) < 0) {
    pthread_cond_wait(&host->cond, &host->mutex);
  }
  pthread_mutex_unlock(&host->mutex);
  // 填充sockaddr_in地址
  saddr->sin_port = payload->sport;
  rte_memcpy(&saddr->sin_addr.s_addr, &payload->sip, sizeof(uint32_t));
  // 3. 数据放入到buffer中
  if (len < payload->length) { // 出现错误,长度小于包长度,重新分配buf大小
    rte_memcpy(buf, payload->data, len);

    ptr = rte_malloc("unsigned char *", payload->length-len, 0);
    rte_memcpy(ptr, payload->data+len, payload->length-len);

    payload->length -= len;
    rte_free(payload->data);
    payload->data = ptr;
    
    rte_ring_mp_enqueue(host->rcvbuf, payload); // 放入到recv buffer中
    return len;
  } else {

    rte_memcpy(buf, payload->data, payload->length); // 直接拷贝到buf中
    rte_free(payload->data);
    rte_free(payload);
    return payload->length;
  }
}

// 1. 准备一个payload结构 2.放入到send buffer中
ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                  const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {
  struct udp_sock_fd *host =  get_hostinfo_fromfd(sockfd);
  if (host == NULL) return -1;

  const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

  struct udp_payload *payload = rte_malloc("offload", sizeof(struct udp_payload), 0);
  if (payload == NULL) return -1;

  payload->dip = daddr->sin_addr.s_addr;
  payload->dport = daddr->sin_port;
  payload->sip = host->localip;
  payload->sport = host->localport;
  payload->length = len;

  char ip_buf[16] = {0};
  printf("nsendto ---> src: %s:%d \n", inet_ntoa2(payload->dip, ip_buf), rte_ntohs(payload->dport));


  payload->data = rte_malloc("unsigned char *", len, 0);
  if (payload->data == NULL) {
    rte_free(payload);
    return -1;
  }

  rte_memcpy(payload->data, buf, len);
  rte_ring_mp_enqueue(host->sndbuf, payload);
  return len;
}
// 关闭socket
int nclose(int fd) {
  struct udp_sock_fd *host =  get_hostinfo_fromfd(fd);
  if (host == NULL) return -1;
  // 链表中移除掉该udp_sock_fd结构
  LL_REMOVE(host, g_lhost);
  // 释放recv buffer和send buffer
  if (host->rcvbuf) {
    rte_ring_free(host->rcvbuf);
  }
  if (host->sndbuf) {
    rte_ring_free(host->sndbuf);
  }
  rte_free(host);
}