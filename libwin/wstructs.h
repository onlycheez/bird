
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

enum wiftype {
  W_IF_UNKOWN = 0,
  W_IF_LOOPBACK,
  W_IF_PTP,
  W_IF_MULTICAST,
  W_IF_BROADCAST
};

enum wkrtsrc {
  W_KRT_SRC_UNKNOWN = 0,
  W_KRT_SRC_REDIRECT,
  W_KRT_SRC_STATIC,
  W_KRT_SRC_UNSPEC
};

enum wdst {
  W_DST_UNKOWN = 0,
  W_DST_ROUTER,
  W_DST_UNREACHABLE
};

struct wifa {
  unsigned long addr;
  unsigned long pxlen;
};

struct wiface {
  char *name;
  unsigned long long luid;
  unsigned flags;
  enum wiftype type;
  unsigned long mtu;
  unsigned long index;
  struct wifa *addrs;
  int addrs_cnt;
  int up;
};

struct wrtentry {
  unsigned long long luid;
  enum wkrtsrc src;
  unsigned next_hop;
  unsigned dst;
  unsigned long pxlen;
  unsigned long metric;
  unsigned long proto_id;
  int is_unreachable;
};

#endif
