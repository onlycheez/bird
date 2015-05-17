/*
 *	BIRD -- Windows Routing Table Syncing
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/krt.h"
#include "libwin/libwin.h"
#include "libwin/wstructs.h"

void
kif_sys_start(struct kif_proto *p UNUSED)
{

}

void
kif_sys_shutdown(struct kif_proto *p)
{

}

void wstruct_free(struct wiface *wiface)
{
  free(wiface->name);
  free(wiface);
}

static void wstruct_fill_iface(struct wiface wif, struct iface *iface)
{
  bzero(iface, sizeof(struct iface));
  bzero(iface->name, sizeof(iface->name));

  memcpy(iface->name, wif.name, strlen(wif.name));
  iface->index = (unsigned)wif.index;
  iface->mtu = (unsigned)wif.mtu;

  // TODO: Setting flags.

  iface->flags |= (IF_MULTIACCESS | IF_MULTICAST);

  if (wif.flags & W_IF_LOOPBACK)
  {
    iface->flags |= (IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE);
  }

  if (wif.up)
  {
    iface->flags |= IF_ADMIN_UP;
    iface->flags |= IF_LINK_UP;
  }

  init_list(&iface->addrs);
  init_list(&iface->neighbors);
}

static void wstruct_fill_ifa(struct wifa *wifa, struct iface *iface,
  struct ifa *ifa)
{
  bzero(ifa, sizeof(struct ifa));
  ifa->iface = if_find_by_index(iface->index);
  if (!ifa->iface)
  {
    printf("Received address message for unknown interface %d\n",
      iface->index);
  }

  if (wifa->pxlen > BITS_PER_IP_ADDRESS)
  {
    printf("KIF: Invalid prefix length for interface %s: %d\n",
      iface->name, wifa->pxlen);
    return;
  }

  ifa->ip = (ip_addr)wifa->addr;
  ipa_ntoh(ifa->ip);

  if (wifa->pxlen == BITS_PER_IP_ADDRESS)
  {
    ip_addr addr = (ip_addr)wifa->addr;
    ipa_ntoh(addr);
    ifa->prefix = ifa->brd = addr;

    /* It is either a host address or a peer address */
    if (ipa_equal(ifa->ip, addr))
      ifa->flags |= IA_HOST;
    else
    {
      ifa->flags |= IA_PEER;
      ifa->opposite = addr;
    }
  }
  else
  {
    ip_addr netmask = ipa_mkmask(ifa->pxlen);
    ifa->prefix = ipa_and(ifa->ip, netmask);
    ifa->brd = ipa_or(ifa->ip, ipa_not(netmask));
    if (wifa->pxlen == BITS_PER_IP_ADDRESS - 1)
      ifa->opposite = ipa_opposite_m1(ifa->ip);

//#ifndef IPV6
//    if (wif->pxlen == BITS_PER_IP_ADDRESS - 2)
//      ifa->opposite = ipa_opposite_m2(ifa->ip);
//
//    if ((iface->flags & IF_BROADCAST) && a[IFA_BROADCAST])
//      {
//        ip_addr xbrd;
//        memcpy(&xbrd, RTA_DATA(a[IFA_BROADCAST]), sizeof(xbrd));
//        ipa_ntoh(xbrd);
//        if (ipa_equal(xbrd, ifa.prefix) || ipa_equal(xbrd, ifa.brd))
//          ifa.brd = xbrd;
//        else if (ifi->flags & IF_TMP_DOWN) /* Complain only during the first scan */
//          log(L_ERR "KIF: Invalid broadcast address %I for %s", xbrd, ifi->name);
//      }
//#endif
  }

  int scope = ipa_classify(ifa->ip);
  if (scope < 0)
  {
    printf("Invalid interface address for %s\n", iface->name);
    return NULL;
  }
  ifa->scope = scope & IADDR_SCOPE_MASK;
}

void
kif_do_scan(struct kif_proto *p UNUSED)
{
  struct wiface *wifaces;
  struct iface iface;
  struct ifa ifa;
  int cnt, i, j;

#ifdef IPV6
  wifaces = win_if_scan(6, &cnt)
#else
  wifaces = win_if_scan(4, &cnt);
#endif

  for (i = 0; i < cnt; i++)
  {
    printf("wif name: %s\n", wifaces[i].name);
    printf("wif mtu: %lu\n", wifaces[i].mtu);
    printf("wif up: %lu\n", wifaces[i].up);

    wstruct_fill_iface(wifaces[i], &iface);

    printf("iface 1: %s\n", ((iface.flags & IF_UP) ? "UP" : "DOWN"));

    if_update(&iface);
    if_end_partial_update(&iface);
    printf("iface 2: %s\n", ((iface.flags & IF_UP) ? "UP" : "DOWN"));

    for (j = 0; j < wifaces[i].addrs_cnt; j++)
    {
      wstruct_fill_ifa(&(wifaces[i].addrs[j]), &iface, &ifa);
      ifa_update(&ifa);
    }

    if_end_partial_update(&iface);
    printf("iface 3: %s\n", ((iface.flags & IF_UP) ? "UP" : "DOWN"));

    // TODO: Delete removed interfaces
    free(wifaces[i].name);
  }

  free(wifaces);
  if_end_update();
}

void
krt_sys_start(struct krt_proto *p)
{

}

void
krt_sys_shutdown(struct krt_proto *p UNUSED)
{

}

void
krt_do_scan(struct krt_proto *p UNUSED)	/* CONFIG_ALL_TABLES_AT_ONCE => p is NULL */
{

}

void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old, struct ea_list *eattrs)
{

}

int
krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
  return 1;
}

int
krt_capable(rte *e)
{
  return 1;
}

void
krt_sys_init_config(struct krt_config *cf)
{

}

void
krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{

}

void
krt_sys_postconfig(struct krt_config *x)
{

}

void
krt_sys_preconfig(struct config *c UNUSED)
{

}
