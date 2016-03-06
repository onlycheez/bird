/*
 *  BIRD -- Windows network interfaces & route tables syncing.
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include "win-types.h"
#include "win-log.h"
#include "win-util.h"

#define MIB_IPROTO_BIRD 11001
#define FAMILY_FROM_IPV(version) ((version == 6) ? AF_INET6 : AF_INET)

/* Must not be used directly but by LIST_LENGTH macro only. */
static void *_list_iter;

/* Count length of IP Helper API linked lists with 'Next' member. */
#define _list_length(list, T, length) \
  _list_iter = list; \
  length = 0; \
  while (_list_iter) \
  { \
    length += 1; \
    _list_iter = (((T) _list_iter)->Next); \
  };

/**
 * Copies interface's ip addresses to struct wiface.
 */
static void _get_adapter_addrs(IP_ADAPTER_UNICAST_ADDRESS *address,
  struct wiface *wiface, int ipv)
{
  if (!address)
  {
    wiface->addrs_cnt = 0;
    return;
  }

  _list_length(address, IP_ADAPTER_UNICAST_ADDRESS *, wiface->addrs_cnt);
  wiface->addrs = wmalloc(wiface->addrs_cnt * sizeof(struct wifa));

  IP_ADAPTER_UNICAST_ADDRESS *addr = address;
  SOCKADDR *sockaddr;
  int idx = 0;

  if (ipv == 6)
  {
    while (addr)
    {
      sockaddr = addr->Address.lpSockaddr;
      memcpy(
        wiface->addrs[idx].addr.u.ipv6.bytes,
        ((struct sockaddr_in6 *) sockaddr)->sin6_addr.u.Byte,
        16);

      wiface->addrs[idx].pxlen = addr->OnLinkPrefixLength;
      addr = addr->Next;
      idx += 1;
    }
  }
  else
  {
    while (addr)
    {
      sockaddr = addr->Address.lpSockaddr;
      wiface->addrs[idx].addr.u.ipv4 =
        ((struct sockaddr_in *)sockaddr)->sin_addr.S_un.S_addr;
      wiface->addrs[idx].pxlen = addr->OnLinkPrefixLength;
      addr = addr->Next;
      idx += 1;
    }
  }
}

/**
 * Converts Windows kernel access enum type to windows-bird compatibility
 * type.
 */
static enum wiftype _access_type(NET_IF_ACCESS_TYPE access_type)
{
  switch (access_type)
  {
    case NET_IF_ACCESS_LOOPBACK:
      return W_IF_LOOPBACK;
    case NET_IF_ACCESS_BROADCAST:
      return W_IF_BROADCAST;
    case NET_IF_ACCESS_POINT_TO_POINT:
      return W_IF_PTP;
    case NET_IF_ACCESS_POINT_TO_MULTI_POINT:
      return W_IF_MULTICAST;
    case NET_IF_ACCESS_MAXIMUM:
    default:
      return W_IF_UNKOWN;
  }
}

/**
 * Returns array of network interfaces structures.
 */
struct wiface* win_if_scan(int ipv, int *cnt)
{
  DWORD retval;
  ULONG size = 15000;
  ULONG family = FAMILY_FROM_IPV(ipv);
  IP_ADAPTER_ADDRESSES *adapters = wmalloc(size);
  MIB_IF_ROW2 adapter_details;

retry:
  retval = GetAdaptersAddresses(
    family,
    GAA_FLAG_INCLUDE_PREFIX |
    GAA_FLAG_SKIP_ANYCAST |
    GAA_FLAG_SKIP_MULTICAST |
    GAA_FLAG_SKIP_FRIENDLY_NAME |
    GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    adapters,
    &size);

  if (retval == ERROR_BUFFER_OVERFLOW)
  {
    goto retry;
  }
  else if (retval != ERROR_SUCCESS)
  {
    win_log_api_error("GetAdaptersAddresses", retval);
    return NULL;
  }

  int length;
  _list_length(adapters, IP_ADAPTER_ADDRESSES*, length);

  struct wiface *wifaces = wmalloc(length * sizeof(struct wiface));
  IP_ADAPTER_ADDRESSES *adapter;
  int idx = 0;

  for (adapter = adapters; adapter; adapter = adapter->Next)
  {
    if (adapter->TunnelType != TUNNEL_TYPE_NONE)
    {
      continue;
    }

    memset(wifaces[idx].name, 0, 64);
    memcpy(wifaces[idx].name, adapter->AdapterName,
      strlen(adapter->AdapterName));
    wifaces[idx].luid = adapter->Luid.Value;
    wifaces[idx].index = adapter->IfIndex;
    wifaces[idx].mtu = adapter->Mtu;

    if (adapter->OperStatus == 1)
    {
      wifaces[idx].is_up = 1;
      _get_adapter_addrs(adapter->FirstUnicastAddress, wifaces + idx, ipv);
    }
    else
    {
      wifaces[idx].is_up = 0;
      wifaces[idx].addrs_cnt = 0;
    }

    adapter_details.InterfaceLuid.Value = 0;
    adapter_details.InterfaceIndex = adapter->IfIndex;
    retval = GetIfEntry2(&adapter_details);
    if (retval != ERROR_SUCCESS)
    {
      win_log_api_error("GetIfEntry2", retval);
    }

    wifaces[idx].type = _access_type(adapter_details.AccessType);
    idx += 1;
  }

  *cnt = idx;
  free(adapters);

  return wifaces;
}

/**
 * Converts Windows kernel protocol enum type to windows-bird compatibility
 * type.
 */
static enum wkrtsrc _proto_type(int proto_type)
{
  switch (proto_type)
  {
    case MIB_IPROTO_BIRD:
      return W_KRT_SRC_BIRD;
    case MIB_IPPROTO_ICMP:
      return W_KRT_SRC_REDIRECT;
    case MIB_IPPROTO_NT_STATIC:
    case MIB_IPPROTO_NT_AUTOSTATIC:
    case MIB_IPPROTO_NETMGMT:
      return W_KRT_SRC_STATIC;
    case MIB_IPPROTO_OTHER:
      return W_KRT_SRC_UNSPEC;
    default:
      return W_KRT_SRC_UNKNOWN;
  }
}

/**
 * Checks whether given interface type is valid (the one BIRD can deal with).
 */
static int _is_iftype_valid(int iftype)
{
  switch (iftype)
  {
    case IF_TYPE_OTHER:
    case IF_TYPE_ETHERNET_CSMACD:
    case IF_TYPE_ISO88025_TOKENRING:
    case IF_TYPE_PPP:
    case IF_TYPE_SOFTWARE_LOOPBACK:
    case IF_TYPE_ATM:
    case IF_TYPE_IEEE80211:
    case IF_TYPE_TUNNEL:
    case IF_TYPE_IEEE1394:
      return 1;
    default:
      return 0;
  }
}

static char _is_route_valid(const MIB_IPFORWARD_ROW2 *route, int ipv)
{
  if ((route->Protocol <= 1 || route->Protocol >= 14) &&
      (!_is_iftype_valid(route->InterfaceLuid.Info.IfType)))
  {
    return 0;
  }

  if (ipv == 6)
  {
    if (route->DestinationPrefix.PrefixLength > 128)
    {
      return 0;
    }

    char i;
    for (i = 0; i < 8; i++)
    {
      if (route->NextHop.Ipv6.sin6_addr.u.Word[i] != 0)
      {
        return 1;
      }
    }

    return 0;
  }
  else
  {
    if ((route->NextHop.Ipv4.sin_addr.S_un.S_addr == 0) ||
        (route->DestinationPrefix.PrefixLength > 32))
    {
      return 0;
    }
  }

  return 1;
}

/**
 * Returns array of structures representing routes found in kernel table.
 */
struct wrtentry* win_rt_scan(int ipv, int *cnt)
{
  DWORD retval;
  ADDRESS_FAMILY family = FAMILY_FROM_IPV(ipv);
  struct wrtentry *rt_entries;
  MIB_IPFORWARD_TABLE2 *routes = NULL;
  MIB_IPFORWARD_ROW2 *route;

  retval = GetIpForwardTable2(family, &routes);
  if (retval != ERROR_SUCCESS)
  {
    win_log_api_error("GetIpForwardTable2", retval);
    return;
  }

  *cnt = routes->NumEntries;
  rt_entries = (struct wrtentry *) wmalloc((*cnt) * sizeof(struct wrtentry));

  int idx, real_count = 0;
  for (idx = 0; idx < *cnt; idx++)
  {
    route = routes->Table + idx;

    if (!_is_route_valid(route, ipv))
    {
      continue;
    }

    rt_entries[real_count].luid = route->InterfaceLuid.Value;
    rt_entries[real_count].src = _proto_type(route->Protocol);
    rt_entries[real_count].metric = route->Metric;
    rt_entries[real_count].proto_id = (int) route->Protocol;

    if (family == AF_INET6)
    {
      memcpy(rt_entries[real_count].next_hop.u.ipv6.bytes,
        route->NextHop.Ipv6.sin6_addr.u.Byte, 16);
      memcpy(rt_entries[real_count].dst.u.ipv6.bytes,
        route->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte, 16);
    }
    else
    {
      rt_entries[real_count].next_hop.u.ipv4 =
        route->NextHop.Ipv4.sin_addr.S_un.S_addr;
      rt_entries[real_count].dst.u.ipv4 =
        route->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
    }
    rt_entries[real_count].pxlen = route->DestinationPrefix.PrefixLength;

    MIB_IPNET_ROW2 ipnet;
    ipnet.InterfaceLuid = route->InterfaceLuid;
    ipnet.Address.Ipv4 = route->NextHop.Ipv4;
    retval = GetIpNetEntry2(&ipnet);

    if (retval != ERROR_SUCCESS)
    {
      win_log_api_error("GetIpNetEntry2", retval);
    }
    else
    {
      rt_entries[real_count].is_unreachable = (ipnet.State == NlnsUnreachable);
    }

    real_count += 1;
  }
  *cnt = real_count;

  FreeMibTable(routes);

  return rt_entries;
}

/**
 * Fill MIB_IPFORWARD_ROW2 strucuture with values from struct wrtentry.
 */
static _wrtentry_to_ipforward_row(const struct wrtentry *entry,
  MIB_IPFORWARD_ROW2 *route, int ipv)
{
  route->DestinationPrefix.PrefixLength = entry->pxlen;

  if (ipv == 6)
  {
    route->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    memcpy(
      route->DestinationPrefix.Prefix.Ipv6.sin6_addr.u.Byte,
      entry->dst.u.ipv6.bytes,
      16);

    route->DestinationPrefix.Prefix.Ipv6.sin6_family = AF_INET6;
    memcpy(
      route->NextHop.Ipv6.sin6_addr.u.Byte,
      entry->next_hop.u.ipv6.bytes,
      16);
  }
  else
  {
    route->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    route->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = entry->dst.u.ipv4;

    route->NextHop.Ipv4.sin_family = AF_INET;
    route->NextHop.Ipv4.sin_addr.S_un.S_addr = entry->next_hop.u.ipv4;
  }
}

/**
 * Delete route netry from kernel table.
 */
void win_rt_delete(const struct wrtentry *entry, int ipv)
{
  MIB_IPFORWARD_ROW2 route;
  route.InterfaceLuid.Value = entry->luid;
  _wrtentry_to_ipforward_row(entry, &route, ipv);

  int retval = DeleteIpForwardEntry2(&route);
  if (retval != ERROR_SUCCESS)
  {
    win_log_api_error("DeleteIpForwardEntry2", retval);
  }
}

/**
 * Create route entry in kernel table.
 */
void win_rt_create(const struct wrtentry *entry, int ipv)
{
  int retval;
  MIB_IPFORWARD_ROW2 route;
  InitializeIpForwardEntry(&route);

  route.InterfaceLuid.Value = entry->luid;
  _wrtentry_to_ipforward_row(entry, &route, ipv);

  route.Loopback = FALSE;
  route.Metric = -1;
  route.Protocol = MIB_IPROTO_BIRD;

  retval = CreateIpForwardEntry2(&route);
  if (retval != ERROR_SUCCESS)
  {
    win_log_api_error("CreateIpForwardEntry2", retval);
  }
}
