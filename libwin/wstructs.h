
#ifndef _WINDOWS_STRUCT_H_
#define _WINDOWS_STRUCT_H_

struct wiface {
  char *name;
  unsigned flags;
  unsigned long mtu;
  unsigned long index;			/* OS-dependent interface index */
  unsigned oper_status;
  //list addrs;				/* Addresses assigned to this interface */
  //struct wifa *addr;			/* Primary address */
};

#endif
