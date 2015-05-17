
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

struct wifa {
  unsigned long addr;
  unsigned long pxlen;
};

struct wiface {
  char *name;
  unsigned flags;
  unsigned long mtu;
  unsigned long index;			/* OS-dependent interface index */
  unsigned oper_status;
  unsigned long ipv4_addr;
  struct wifa **uni_addrs;
  unsigned long pxlen;
  int is_loopback;
};

#endif
