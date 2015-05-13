
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

struct wiface {
  char *name;
  unsigned flags;
  unsigned long mtu;
  unsigned long index;			/* OS-dependent interface index */
  unsigned oper_status;
  unsigned long ipv4_addr;
  unsigned prefix;
  unsigned long prefix_len;
  int is_loopback;
};

#endif
