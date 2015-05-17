
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

#define W_IF_LOOPBACK  1
#define W_IF_MULTICAST 1 << 1
#define W_IF_BROADCAST 1 << 2

struct wifa {
  unsigned long addr;
  unsigned long pxlen;
};

struct wiface {
  char *name;
  unsigned flags;
  unsigned long mtu;
  unsigned long index;
  struct wifa *addrs;
  int addrs_cnt;
  int up;
};

#endif
