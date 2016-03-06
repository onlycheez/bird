/*
 *  BIRD -- Layer between Windows & BIRD.
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_WIN_TYPES_H_
#define _BIRD_WIN_TYPES_H_

#include <stdint.h>

/**
 * Defines mappings between winsock library and bird.
 *
 * Windows IP Helper API cannot be called directly from BIRD because Windows
 * system headers collide with Unix system headers.
 * So values and types from IP Helper are converted to structs and types defined
 * here. This header is then included in both libwin module (calling winapi)
 * and BIRD sysdep module.
 */

/**
 * Interface type.
 */
enum wiftype {
  W_IF_UNKOWN = 0,
  W_IF_LOOPBACK,
  W_IF_PTP,
  W_IF_MULTICAST,
  W_IF_BROADCAST
};

/**
 * Route entry source.
 */
enum wkrtsrc {
  W_KRT_SRC_UNKNOWN = 0,
  W_KRT_SRC_BIRD,
  W_KRT_SRC_REDIRECT,
  W_KRT_SRC_STATIC,
  W_KRT_SRC_UNSPEC
};

/**
 * Destination type.
 */
enum wdst {
  W_DST_UNKOWN = 0,
  W_DST_ROUTER,
  W_DST_UNREACHABLE
};

/**
 * IP address.
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
 * Network interface address.
 */
struct wifa {
  struct wip addr;
  uint32_t pxlen;
};

/**
 * Network interface.
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
 * Route entry.
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
