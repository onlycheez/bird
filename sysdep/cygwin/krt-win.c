/*
 *  BIRD -- Windows Routing Table Syncing
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/krt.h"
#include "sysdep/cygwin/libwin/win-krt.h"
#include "sysdep/cygwin/libwin/win-types.h"

#define SKIP(ARG...) do { DBG("KRT: Ignoring route - " ARG); return; } while(0)

void kif_sys_start(struct kif_proto *p UNUSED)
{

}

void kif_sys_shutdown(struct kif_proto *p)
{

}

/**
 * Copies values from struct wiface to struct iface.
 */
static void _wiface_to_iface(const struct wiface *wiface, struct iface *iface)
{
  bzero(iface, sizeof(struct iface));
  bzero(iface->name, sizeof(iface->name));

  memcpy(iface->name, wiface->name, strlen(wiface->name));
  iface->index = (unsigned) wiface->index;
  iface->mtu = (unsigned) wiface->mtu;
  iface->luid = wiface->luid;

  switch (wiface->type)
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

  if (wiface->is_up)
  {
    iface->flags |= IF_ADMIN_UP;
    iface->flags |= IF_LINK_UP;
  }

  init_list(&iface->addrs);
  init_list(&iface->neighbors);
}

/**
 * Assigns value of struct wip to ip_addr. Handles IP versions.
 * Result is Little Endian.
 */
static void _wip_to_ip_addr(const struct wip *src, ip_addr *dst)
{
#ifdef IPV6
  *dst = IPA_NONE;
  int i;
  for (i = 0; i < 16; i++)
  {
    dst->addr[i / 4] |= src->u.ipv6.bytes[i] << ((3 - (i % 4)) * 8);
  }
#else
  *dst = src->u.ipv4;
  ipa_ntoh(*dst);
#endif
}

/**
 * Assigns value of ip_addr to struct wip. Handles IP versions.
 * Result is Big Endian.
 */
static void _ip_addr_to_wip(const ip_addr *src, struct wip *dst)
{
#ifdef IPV6
  int i, j;
  for (i = 0; i < 16; i++)
  {
    j = i / 4;
    dst->u.ipv6.bytes[i] = src->addr[j] >> (24 - ((i % 4) * 8));
  }
#else
  dst->u.ipv4 = *src;
  ipa_hton(dst->u.ipv4);
#endif
}

/**
 * Converts struct wifa to struct ifa and associates with struct iface.
 *
 */
static void _wifa_to_ifa(const struct wifa *wifa, struct iface *iface,
  struct ifa *ifa)
{
  bzero(ifa, sizeof(struct ifa));
  ifa->iface = if_find_by_index(iface->index);
  if (!ifa->iface)
  {
    log(L_ERR "KIF: Received address message for unknown interface %d",
      iface->index);
    return;
  }

  if (wifa->pxlen > BITS_PER_IP_ADDRESS)
  {
    log(L_ERR "KIF: Invalid prefix length for interface %s: %d\n",
      iface->name, wifa->pxlen);
    return;
  }

  ifa->pxlen = wifa->pxlen;
  _wip_to_ip_addr(&wifa->addr, &ifa->ip);

  if (wifa->pxlen == BITS_PER_IP_ADDRESS)
  {
    ip_addr addr;
    _wip_to_ip_addr(&wifa->addr, &addr);
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
    {
      ifa->opposite = ipa_opposite_m1(ifa->ip);
    }
  }

  int scope = ipa_classify(ifa->ip);
  if (scope < 0)
  {
    log(L_ERR "KIF: Invalid interface address %I for %s", ifa->ip, iface->name);
    return;
  }
  ifa->scope = scope & IADDR_SCOPE_MASK;
}

void kif_do_scan(struct kif_proto *p UNUSED)
{
  struct wiface *wifaces;
  struct iface iface;
  struct ifa ifa;
  int cnt, i, j;

#ifdef IPV6
  wifaces = win_if_scan(6, &cnt);
#else
  wifaces = win_if_scan(4, &cnt);
#endif

  for (i = 0; i < cnt; i++)
  {
    _wiface_to_iface(wifaces + i, &iface);

    if_update(&iface);
    if_end_partial_update(&iface);

    for (j = 0; j < wifaces[i].addrs_cnt; j++)
    {
      _wifa_to_ifa(&(wifaces[i].addrs[j]), &iface, &ifa);
      ifa_update(&ifa);
    }

    if_end_partial_update(&iface);
  }

  free(wifaces);
  if_end_update();
}

int krt_sys_start(struct krt_proto *p)
{
  return 1;
}

void krt_sys_shutdown(struct krt_proto *p UNUSED)
{

}

static int _wkrtsrc_to_alleged_route_source(enum wkrtsrc src)
{
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

static void _wkrt_parse_route(struct krt_proto *p, struct wrtentry *wrtentry)
{
  ip_addr idst, igw;
  _wip_to_ip_addr(&wrtentry->dst, &idst);
  _wip_to_ip_addr(&wrtentry->next_hop, &igw);

  int c = ipa_classify_net(idst);
  if ((c < 0) || !(c & IADDR_HOST) || ((c & IADDR_SCOPE_MASK) <= SCOPE_LINK))
  {
    SKIP("strange class/scope\n");
  }

  rte *re;
  rta ra = {
    .src= p->p.main_source,
    .source = RTS_INHERIT,
    .scope = SCOPE_UNIVERSE,
    .cast = RTC_UNICAST
  };
  net *net = net_get(p->p.table, idst, wrtentry->pxlen);

  if (wrtentry->is_unreachable)
  {
    ra.dest = RTD_UNREACHABLE;
    goto done;
  }

  ra.iface = if_find_by_luid(wrtentry->luid);
  if (!ra.iface)
  {
    SKIP("iface with luid %lx not found", wrtentry->luid);
  }

  if (ipa_nonzero2(igw))
  {
    /* There is some gateway in the way. */
    ra.dest = RTD_ROUTER;
    ra.gw = igw;

    neighbor *ng = neigh_find2(&p->p, &ra.gw, ra.iface, 0);
    if (!ng || (ng->scope == SCOPE_HOST))
    {
      log(L_ERR "KRT: Received route %I/%d with strange next-hop %I",
        net->n.prefix, net->n.pxlen, ra.gw);
      return;
    }
  }
  else
  {
    /* This is a host route or a loobpack route. */
    ra.dest = RTD_DEVICE;
  }

done:
  re = rte_get_temp(&ra);
  re->net = net;
  re->u .krt.src = _wkrtsrc_to_alleged_route_source(wrtentry->src);
  re->u.krt.proto = wrtentry->proto_id;
  re->u.krt.type = 0;
  //re->u.krt.metric = (entry->metric == -1) ? 0 : entry->metric;
  re->u.krt.metric = 0;

  krt_got_route(p, re);
}

void krt_do_scan(struct krt_proto *p)
{
  struct wrtentry *wrtentries;
  int idx, cnt;

#ifdef IPV6
  wrtentries = win_rt_scan(6, &cnt);
#else
  wrtentries = win_rt_scan(4, &cnt);
#endif

  for (idx = 0; idx < cnt; idx++)
  {
    _wkrt_parse_route(p, wrtentries + idx);
  }

  free(wrtentries);
}

static void _wrt_entry_init(struct wrtentry *wrtentry, rte *re)
{
  net *net = re->net;
  rta *ra = re->attrs;
  struct iface *iface = ra->iface;

  wrtentry->luid = iface->luid;
  wrtentry->proto_id = KRT_SRC_BIRD;

  if (ra->dest == RTD_ROUTER)
  {
    _ip_addr_to_wip(&net->n.prefix, &wrtentry->dst);
    _ip_addr_to_wip(&ra->gw, &wrtentry->next_hop);
    wrtentry->pxlen = net->n.pxlen;
  }
  else if (ra->dest == RTD_DEVICE)
  {
#ifdef IPV6
    bzero(wrtentry->next_hop.u.ipv6.bytes, 16);
#else
    wrtentry->next_hop.u.ipv4 = 0;
#endif
    _ip_addr_to_wip(&net->n.prefix, &wrtentry->dst);
    wrtentry->pxlen = net->n.pxlen;
  }
  else if (ra->dest == RTD_BLACKHOLE)
  {
    /* Windows doesn't support blackhole so invalid ip is used instead. */
#ifdef IPV6
    bzero(wrtentry->dst.u.ipv6.bytes, 16);
    bzero(wrtentry->next_hop.u.ipv6.bytes, 16);
#else
    wrtentry->dst.u.ipv4 = 0;
    wrtentry->next_hop.u.ipv4 = 0;
#endif
    wrtentry->pxlen = MAX_PREFIX_LENGTH;
  }
  else
  {
    DBG("Unhandled destination type: %d\n", ra->dest);
  }
}

void krt_replace_rte(struct krt_proto *p, net *n, rte *new, rte *old,
  struct ea_list *eattrs)
{
  struct wrtentry entry;

  if (old)
  {
    _wrt_entry_init(&entry, old);
#ifdef IPV6
    win_rt_delete(&entry, 6);
#else
    win_rt_delete(&entry, 4);
#endif
  }

  if (new)
  {
    _wrt_entry_init(&entry, new);
#ifdef IPV6
    win_rt_create(&entry, 6);
#else
    win_rt_create(&entry, 4);
#endif
  }
}

int krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n, struct krt_config *o)
{
  return 1;
}

int krt_capable(rte *e)
{
  return 1;
}

void krt_sys_init_config(struct krt_config *cf)
{

}

void krt_sys_copy_config(struct krt_config *d, struct krt_config *s)
{

}

void krt_sys_postconfig(struct krt_config *x)
{

}

void krt_sys_preconfig(struct config *c UNUSED)
{

}
