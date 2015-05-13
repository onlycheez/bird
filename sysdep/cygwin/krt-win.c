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

static struct iface* wstruct_convert_iface(struct wiface *wif)
{
  struct iface *iface = xmalloc(sizeof(struct iface));
  bzero(iface, sizeof(struct iface));
  bzero(iface->name, sizeof(iface->name));

  memcpy(iface->name, wif->name, strlen(wif->name));
  iface->index = (unsigned)wif->index;
  iface->mtu = (unsigned)wif->mtu;

  // TODO: Setting flags.

  iface->flags |= (IF_MULTIACCESS | IF_MULTICAST);

  if (wif->is_loopback)
  {
    iface->flags |= (IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE);
  }

  if (!(wif->flags & 0x10))
  {
    iface->flags |= IF_MULTICAST;
  }

  if (wif->oper_status == 1)
  {
    iface->flags |= IF_UP;
    iface->flags |= IF_ADMIN_UP;
    iface->flags |= IF_LINK_UP;
  }
  else if (wif->oper_status == 7)
  {
  }

  init_list(&iface->addrs);
  init_list(&iface->neighbors);

  return iface;
}

static struct ifa* wstruct_convert_ifa(struct wiface *wif, struct iface *iface)
{
  struct ifa *ifa = xmalloc(sizeof(ifa));
  bzero(ifa, sizeof(struct ifa));
  ifa->iface = if_find_by_index(iface->index);
  if (!ifa->iface)
  {
    printf("Received address message for unknown interface %d",
      iface->index);
  }

  ifa->ip = (ip_addr)wif->ipv4_addr;
  ipa_ntoh(ifa->ip);

  ifa->pxlen = wif->prefix_len;
  ip_addr prefix = wif->prefix;
  ipa_ntoh(prefix);
  ifa->prefix = ifa->brd = prefix;

  /* It is either a host address or a peer address */
  if (ipa_equal(ifa->ip, prefix))
    ifa->flags |= IA_HOST;
  else
  {
    ifa->flags |= IA_PEER;
    ifa->opposite = prefix;
  }

  int scope = ipa_classify(ifa->ip);
  if (scope < 0)
  {
    printf("Invalid interface address for %s\n", iface->name);
    return NULL;
  }
  ifa->scope = scope & IADDR_SCOPE_MASK;

  return ifa;
}

void
kif_do_scan(struct kif_proto *p UNUSED)
{
  struct wiface *wiface;
  struct iface *iface;
  struct ifa *ifa;

  if (win_if_update_in_progess())
  {
    return;
  }

  if_start_update();

#ifdef IPV6
  win_if_scan(6)
#else
  win_if_scan(4);
#endif

  while (wiface = win_if_next())
  {
    printf("wif name: %s\n", wiface->name);
    printf("wif mtu: %lu\n", wiface->mtu);
    printf("wif status: %lu\n", wiface->oper_status);
    printf("wif addr: %lu\n", wiface->ipv4_addr);

    iface = wstruct_convert_iface(wiface);

    printf("iface 1: %s\n", ((iface->flags & IF_UP) ? "UP" : "DOWN"));

    if_update(iface);
    if_end_partial_update(iface);
    printf("iface 2: %s\n", ((iface->flags & IF_UP) ? "UP" : "DOWN"));
    ifa = wstruct_convert_ifa(wiface, iface);
    free(wiface->name);
    free(wiface);
    if (!ifa)
    {
      continue;
    }

    ifa_update(ifa);
    if_end_partial_update(iface);
    printf("iface 3: %s\n", ((iface->flags & IF_UP) ? "UP" : "DOWN"));

    // TODO: Delete removed interfaces
  }

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
