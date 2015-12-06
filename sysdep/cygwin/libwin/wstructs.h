
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

#include <stdint.h>

/**
 * Interface type
 */
enum wiftype {
  W_IF_UNKOWN = 0,
  W_IF_LOOPBACK,
  W_IF_PTP,
  W_IF_MULTICAST,
  W_IF_BROADCAST
};

/**
 * Route entry source
 */
enum wkrtsrc {
  W_KRT_SRC_UNKNOWN = 0,
  W_KRT_SRC_BIRD,
  W_KRT_SRC_REDIRECT,
  W_KRT_SRC_STATIC,
  W_KRT_SRC_UNSPEC
};

/**
 * Destination type
 */
enum wdst {
  W_DST_UNKOWN = 0,
  W_DST_ROUTER,
  W_DST_UNREACHABLE
};

/**
 * IP address
 */
struct wip {
  union {
    uint32_t ipv4;
    struct {
      unsigned char bytes[16];
    } ipv6;
  } u;
};

/**
 * Network interface address
 */
struct wifa {
  struct wip addr;
  uint32_t pxlen;
};

/**
 * Netowrk interface
 */
struct wiface {
  char name[64];
  uint64_t luid;
  enum wiftype type;
  uint32_t mtu;
  uint32_t index;
  struct wifa *addrs;
  int addrs_cnt;
  char is_up;
};

/**
 * Route entry
 */
struct wrtentry {
  uint64_t luid;
  enum wkrtsrc src;
  struct wip next_hop;
  struct wip dst;
  uint32_t pxlen;
  unsigned long metric;
  unsigned proto_id;
  char is_unreachable;
};

#endif
