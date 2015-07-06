
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>

#include "wstructs.h"

/* GUID length + 2 for parenthesis */
#define GUID_LENGTH 39
#define MIB_IPROTO_BIRD 11001

static void *list_iter;
#define LIST_LENGTH(list, T, length) \
  list_iter = (void *)list; \
  length = 0; \
  while (list_iter) \
  { \
    length += 1; \
    list_iter = (void *)(((T)list_iter)->Next); \
  };

void die(const char *msg, ...) __attribute__((noreturn));

LPVOID wmalloc(ULONG size)
{
  void *p = malloc(size);
  if (p)
  {
    return p;
  }
  die("Unable to allocate %d bytes of memory", size);
}

LPVOID wrealloc(void *ptr, ULONG size)
{
  void *p = realloc(ptr, size);
  if (p)
  {
    return p;
  }
  die("Unable to allocate %d bytes of memory", size);
}

static char* get_error_msg(DWORD retval)
{
  DWORD code = (retval == 0) ? GetLastError() : retval;
  LPSTR buffer = NULL;
  size_t size = 0;

  if (code == 0)
  {
    size = 16;
    buffer = "No error message";
  }
  else
  {
    size = FormatMessageA(
      FORMAT_MESSAGE_ALLOCATE_BUFFER |
      FORMAT_MESSAGE_FROM_SYSTEM |
      FORMAT_MESSAGE_IGNORE_INSERTS,
      NULL, code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&buffer, 0, NULL);
  }

  char *msg = wmalloc(size + 1);
  memset(msg, 0, size + 1);
  memcpy(msg, buffer, size);

  LocalFree(buffer);

  return msg;
}

static wlog(const char *format, ...)
{
  va_list ap;
  va_start(ap, format);
  vfprintf(stderr, format, ap);
  va_end(ap);
}

#define log_winapi_error(fc_name, retval) \
  char *msg = get_error_msg(retval); \
  wlog(fc_name " failed (0x%x). %s", retval, msg); \
  free(msg);

PSTR narrow_wstr(PCWSTR wstr)
{
  int length = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  PSTR str = (PSTR)wmalloc(length);
  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, length, NULL, NULL);
  return str;
}

void get_addrs(IP_ADAPTER_UNICAST_ADDRESS *address, struct wiface *wiface,
  int *idx)
{
  IP_ADAPTER_UNICAST_ADDRESS *addr = address;

  while (addr)
  {
    SOCKADDR *sockaddr = addr->Address.lpSockaddr;
    wiface->addrs[*idx].addr =
      ((struct sockaddr_in *)sockaddr)->sin_addr.S_un.S_addr;
    wiface->addrs[*idx].pxlen = addr->OnLinkPrefixLength;
    addr = addr->Next;
    *idx += 1;
  }
}

static enum wiftype convert_access_type(NET_IF_ACCESS_TYPE access_type)
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

struct wiface* win_if_scan(int ipv, int *cnt)
{
  DWORD retval;
  ULONG size = 15000;
  ULONG family = (ipv == 6) ? AF_INET6 : AF_INET;
  IP_ADAPTER_ADDRESSES *adapters = wmalloc(size);

  MIB_IF_ROW2 adapter_details;
  int adapt_cnt, addr_idx;

retry:
  retval = GetAdaptersAddresses(family,
    GAA_FLAG_INCLUDE_PREFIX |
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
    log_winapi_error("GetAdaptersAddresses", retval);
    return NULL;
  }

  LIST_LENGTH(adapters, IP_ADAPTER_ADDRESSES*, adapt_cnt);

  struct wiface *wifaces = wmalloc(adapt_cnt * sizeof(struct wiface));
  IP_ADAPTER_ADDRESSES *adapter = adapters;
  int idx = 0;
  while (adapter)
  {
    wifaces[idx].flags = 0;
    wifaces[idx].name = strdup(adapter->AdapterName);
    wifaces[idx].luid = adapter->Luid.Value;
    wifaces[idx].index = adapter->IfIndex;
    wifaces[idx].mtu = adapter->Mtu;

    if (adapter->OperStatus != 1)
    {
      wifaces[idx].up = 0;
      wifaces[idx].addrs_cnt = 0;
      goto loopend;
    }

    wifaces[idx].up = 1;
    LIST_LENGTH(adapter->FirstUnicastAddress,
      IP_ADAPTER_UNICAST_ADDRESS *,
      wifaces[idx].addrs_cnt);
    wifaces[idx].addrs = wmalloc(wifaces[idx].addrs_cnt * sizeof(struct wifa));

    addr_idx = 0;

    if (adapter->FirstUnicastAddress)
    {
      get_addrs(
        (IP_ADAPTER_UNICAST_ADDRESS *)adapter->FirstUnicastAddress,
        &wifaces[idx], &addr_idx);
    }

    //if (adapter->FirstMulticastAddress)
    //{
    //  get_addrs(
    //    (IP_ADAPTER_UNICAST_ADDRESS_LH *)adapter->FirstMulticastAddress,
    //    &wifaces[idx], &addr_idx);
    //  wifaces[idx].flags |= W_IF_MULTICAST;
    //}
    //
    //if (adapter->FirstAnycastAddress)
    //{
    //  get_addrs(
    //    (IP_ADAPTER_UNICAST_ADDRESS_LH *)adapter->FirstAnycastAddress,
    //    &wifaces[idx], &addr_idx);
    //  wifaces[idx].flags |= W_IF_MULTICAST;
    //}

loopend:
    adapter_details.InterfaceLuid.Value = 0;
    adapter_details.InterfaceIndex = adapter->IfIndex;
    retval = GetIfEntry2(&adapter_details);
    if (retval != ERROR_SUCCESS)
    {
      log_winapi_error("GetIfEntry2", retval);
    }

    wifaces[idx].type = convert_access_type(adapter_details.AccessType);

    idx += 1;
    adapter = adapter->Next;
  }

  *cnt = adapt_cnt;
  free(adapters);

  return wifaces;
}

static enum wkrtsrc convert_proto_type(int winapi_proto_type)
{
  // TODO: How should be KRT_SRC_KERNEL set?
  switch (winapi_proto_type)
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

static int is_iftype_valid(int iftype)
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

char ipstr[16];
char luidstr[256];

struct wrtentry* win_rt_scan(int ipv, int *cnt)
{
  DWORD retval;
  ADDRESS_FAMILY family = (ipv == 6) ? AF_INET6 : AF_INET;
  struct wrtentry *rt_entries;
  MIB_IPFORWARD_TABLE2 *routes = NULL;
  MIB_IPFORWARD_ROW2 *route;

  retval = GetIpForwardTable2(family, &routes);
  if (retval != ERROR_SUCCESS)
  {
    log_winapi_error("GetIpForwardTable2", retval);
    return;
  }

  *cnt = routes->NumEntries;
  rt_entries = (struct wrtentry *)wmalloc(*cnt * sizeof(struct wrtentry));

  int idx, real_count = 0;
  for (idx = 0; idx < *cnt; idx++)
  {
    route = routes->Table + idx;

    if (route->NextHop.Ipv4.sin_addr.S_un.S_addr == 0 || // IPV6
        !is_iftype_valid(route->InterfaceLuid.Info.IfType) ||
        route->DestinationPrefix.PrefixLength > 32 ||
        !(route->Protocol >= 1 && route->Protocol <= 14))
    {
      continue;
    }

    rt_entries[real_count].luid = route->InterfaceLuid.Value;
    rt_entries[real_count].src = convert_proto_type(route->Protocol);
    rt_entries[real_count].metric = route->Metric;
    rt_entries[real_count].proto_id = (int)route->Protocol;
    if (family == AF_INET6)
    {
    }
    else
    {
      rt_entries[real_count].next_hop = route->NextHop.Ipv4.sin_addr.S_un.S_addr;
      rt_entries[real_count].dst = route->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
      rt_entries[real_count].pxlen = route->DestinationPrefix.PrefixLength;
    }

    MIB_IPNET_ROW2 ipnet;
    ipnet.InterfaceLuid = route->InterfaceLuid;
    ipnet.Address.Ipv4 = route->NextHop.Ipv4;
    retval = GetIpNetEntry2(&ipnet);
    if (retval != ERROR_SUCCESS)
    {
      log_winapi_error("GetIpNetEntry2", retval);
    }
    else
    {
      // TODO: How about other states?
      rt_entries[real_count].is_unreachable = (ipnet.State == NlnsUnreachable);
    }

    real_count += 1;
  }
  *cnt = real_count;

  FreeMibTable(routes);

  return rt_entries;
}

static ip_forward_entry_set_addresses(MIB_IPFORWARD_ROW2 *route,
  struct wrtentry *entry, int ipv)
{
  if (ipv == 6)
  {

  }
  else
  {
    route->DestinationPrefix.PrefixLength = entry->pxlen;
    route->DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    route->DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = entry->dst;

    route->NextHop.Ipv4.sin_family = AF_INET;
    route->NextHop.Ipv4.sin_addr.S_un.S_addr = entry->next_hop;
  }
}

void win_rt_delete(struct wrtentry *entry, int ipv)
{
  MIB_IPFORWARD_ROW2 route;
  route.InterfaceLuid.Value = entry->luid;
  ip_forward_entry_set_addresses(&route, entry, ipv);

  int retval = DeleteIpForwardEntry2(&route);
  if (retval != ERROR_SUCCESS)
  {
    log_winapi_error("DeleteIpForwardEntry2", retval);
  }
}

void win_rt_create(struct wrtentry *entry, int ipv)
{
  int retval;
  MIB_IPFORWARD_ROW2 route;
  InitializeIpForwardEntry(&route);

  route.InterfaceLuid.Value = entry->luid;
  ip_forward_entry_set_addresses(&route, entry, ipv);

  route.Loopback = FALSE;
  route.Metric = -1;
  route.Protocol = MIB_IPROTO_BIRD;

  retval = CreateIpForwardEntry2(&route);
  if (retval != ERROR_SUCCESS)
  {
    log_winapi_error("CreateIpForwardEntry2", retval);
  }
}
