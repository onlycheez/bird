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
  iface->luid = wif.luid;

  // TODO: Setting flags.
  switch (wif.type)
  {
    case W_IF_LOOPBACK:
      iface->flags |= IF_MULTIACCESS | IF_LOOPBACK | IF_IGNORE;
      break;
    case W_IF_PTP:
      iface->flags |= IF_MULTICAST;
      break;
    case W_IF_BROADCAST:
      iface->flags |= IF_MULTIACCESS | IF_BROADCAST | IF_MULTICAST;
      break;
    case W_IF_MULTICAST:
    default:
      iface->flags |= IF_MULTICAST;
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

  ifa->pxlen = wifa->pxlen;
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
    return;
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
    wstruct_fill_iface(wifaces[i], &iface);

    if_update(&iface);
    if_end_partial_update(&iface);

    for (j = 0; j < wifaces[i].addrs_cnt; j++)
    {
      wstruct_fill_ifa(&(wifaces[i].addrs[j]), &iface, &ifa);
      ifa_update(&ifa);
    }

    if_end_partial_update(&iface);

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

static int alleged_route_source(enum wkrtsrc src)
{
  // TODO: When return RTPROT_BIRD?
  switch (src)
  {
    case W_KRT_SRC_BIRD:
      return KRT_SRC_BIRD;
    case W_KRT_SRC_REDIRECT:
      return KRT_SRC_REDIRECT;
    case W_KRT_SRC_UNSPEC:
      return KRT_SRC_UNKNOWN;
    case W_KRT_SRC_STATIC:
    case W_KRT_SRC_UNKNOWN:
    default:
      return KRT_SRC_ALIEN;
  }
}

static void wkrt_parse_route(struct krt_proto *p, struct wrtentry *entry)
{
  // TODO: Check whether Windows supports multipath.

  ip_addr idst, igw;
  idst = entry->dst;
  ipa_ntoh(idst);
  igw = entry->next_hop;
  ipa_ntoh(igw);

  int c = ipa_classify_net(idst);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    printf("strange class/scope\n");
    return;
  }

  rte *re;
  rta ra = {
    .src= p->p.main_source,
    .source = RTS_INHERIT,
    .scope = SCOPE_UNIVERSE,
    .cast = RTC_UNICAST
  };
  net *net = net_get(p->p.table, idst, entry->pxlen);

  if (entry->is_unreachable)
  {
    ra.dest = RTD_UNREACHABLE;
    goto done;
  }

  ra.iface = if_find_by_luid(entry->luid);
  if (!ra.iface)
  {
    printf("wstruct_fill_rta: iface with luid %lx not found.\n", entry->luid);
    return;
  }

  if (entry->next_hop != 0)
  {
    /* There is some gateway in the way. */
    ra.dest = RTD_ROUTER;
    ra.gw = igw;

    neighbor *ng = neigh_find2(&p->p, &ra.gw, ra.iface, 0);
    if (!ng || (ng->scope == SCOPE_HOST))
    {
      printf("KRT: Received route %lu/%d with strange next-hop %lu",
          net->n.prefix, net->n.pxlen, ra.gw);
      return;
    }
  }
  else
  {
    /* This is a host route or a loobpack route. */
    printf("RTD_DEVICE\n");
    ra.dest = RTD_DEVICE;
  }

done:
  re = rte_get_temp(&ra);
  re->net = net;
  re->u.krt.src = alleged_route_source(entry->src);
  re->u.krt.proto = entry->proto_id;
  re->u.krt.type = 0;
  //re->u.krt.metric = (entry->metric == -1) ? 0 : entry->metric;
  re->u.krt.metric = 0;

  krt_got_route(p, re);

  // TODO: Maybe other rte members. See netlink.
}

void
krt_do_scan(struct krt_proto *p)
{
  struct wrtentry *entries;
  int idx, cnt;

#ifdef IPV6
  entries = win_rt_scan(6, &cnt);
#else
  entries = win_rt_scan(4, &cnt);
#endif

  for (idx = 0; idx < cnt; idx++)
  {
    wkrt_parse_route(p, entries + idx);
  }

  free(entries);
}

static void wstruct_init_wrtentry(struct wrtentry *entry, rte *re)
{
  net *net = re->net;
  rta *ra = re->attrs;
  struct iface *iface = ra->iface;

  entry->luid = iface->luid;
  entry->proto_id = KRT_SRC_BIRD;

  if (ra->dest == RTD_ROUTER)
  {
    entry->dst = net->n.prefix;
    ipa_hton(entry->dst);
    entry->next_hop = ra->gw;
    ipa_hton(entry->next_hop);
    entry->pxlen = net->n.pxlen;
  }
  else if (ra->dest == RTD_DEVICE)
  {
    entry->next_hop = 0;
    entry->dst = net->n.prefix;
    ipa_hton(entry->dst);
    entry->pxlen = net->n.pxlen;
  }
  else if (ra->dest == RTD_BLACKHOLE)
  {
    /* Windows doesn't support blackhole so invalid ip is used instead. */
    entry->dst = 0;
    entry->next_hop = 0;
    entry->pxlen = MAX_PREFIX_LENGTH;
  }
  else
  {
    printf("Unhandled destination type: %d\n", ra->dest);
  }
}

void
krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old,
  struct ea_list *eattrs)
{
  struct wrtentry entry;

  if (old)
  {
    wstruct_init_wrtentry(&entry, old);
#ifdef IPV6
    win_rt_delete(&entry, 6);
#else
    win_rt_delete(&entry, 4);
#endif
  }

  if (new)
  {
    wstruct_init_wrtentry(&entry, new);
#ifdef IPV6
    win_rt_create(&entry, 6);
#else
    win_rt_create(&entry, 4);
#endif
  }
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
