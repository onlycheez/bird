
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

#define W_IF_LOOPBACK  1
#define W_IF_MULTICAST 1 << 1
#define W_IF_BROADCAST 1 << 2

enum wkrtsrc {
  W_KRT_SRC_UNKNOWN = 0,
  W_KRT_SRC_REDIRECT,
  W_KRT_SRC_STATIC,
  W_KRT_SRC_UNSPEC
};

struct wifa {
  unsigned long addr;
  unsigned long pxlen;
};

struct wiface {
  char *name;
  unsigned long luid;
  unsigned flags;
  unsigned long mtu;
  unsigned long index;
  struct wifa *addrs;
  int addrs_cnt;
  int up;
};

struct wrtentry {
  unsigned long luid;
  enum wkrtsrc src;
  unsigned long next_hop;
  unsigned long metric;
};

#endif
