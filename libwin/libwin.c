
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <Mstcpip.h>

#include <stdio.h>

#include "wstructs.h"

/* GUID length + 2 for parenthesis */
#define GUID_LENGTH 39

void die(const char *msg, ...) __attribute__((noreturn));

LPVOID wmalloc(ULONG size)
{
  void *p = malloc(size);
  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}

LPVOID wrealloc(void *ptr, ULONG size)
{
  void *p = realloc(ptr, size);
  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}

PSTR narrow_wstr(PCWSTR wstr)
{
  int length = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  PSTR str = (PSTR)wmalloc(length);
  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, length, NULL, NULL);
  return str;
}

int addr_list_length(IP_ADAPTER_UNICAST_ADDRESS *address)
{
  IP_ADAPTER_UNICAST_ADDRESS *addr = address;
  int count = 0;

  while (addr)
  {
    count += 1;
    addr = (IP_ADAPTER_UNICAST_ADDRESS *)addr->Next;
  }

  return count;
}

int addrs_count(IP_ADAPTER_ADDRESSES *adapter)
{
  int count = 0;

  count += addr_list_length(
    (IP_ADAPTER_UNICAST_ADDRESS *)adapter->FirstUnicastAddress);
  //count += addr_list_length(
  //  (IP_ADAPTER_UNICAST_ADDRESS_LH *)adapter->FirstMulticastAddress);
  //count += addr_list_length(
  //  (IP_ADAPTER_UNICAST_ADDRESS_LH *)adapter->FirstAnycastAddress);

  return count;
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
  printf("win_if_scan called\n");

  ULONG size = 15000;
  DWORD retval = ERROR_SUCCESS;
  ULONG family = AF_INET;
  if (ipv == 6)
    family = AF_INET6;

  IP_ADAPTER_ADDRESSES *adapter, *adapters;
  MIB_IF_ROW2 adapter_details;
  struct wiface *wifaces;
  int i, adapt_cnt, addr_idx;

  adapters = wmalloc(size);

  retval = GetAdaptersAddresses(AF_INET,
    GAA_FLAG_INCLUDE_PREFIX |
    GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    adapters,
    &size);
  if (retval != ERROR_SUCCESS)
  {
    printf("GetAdaptersAddresses failed (0x%x)\n", retval);
    return;
  }

  adapter = adapters;
  adapt_cnt = 0;
  while (adapter)
  {
    adapt_cnt += 1;
    adapter = adapter->Next;
  }

  wifaces = wmalloc(adapt_cnt * sizeof(struct wiface));
  adapter = adapters;
  i = 0;
  while (adapter)
  {
    wifaces[i].flags = 0;
    wifaces[i].name = strdup(adapter->AdapterName);
    wifaces[i].luid = adapter->Luid.Value;
    printf("GetAdaptersAddresses LUID: 0x%llx\n", adapter->Luid.Value);
    printf("luid Reserved: %u\n", adapter->Luid.Info.Reserved);
    printf("luid NetLuidIndex: %u\n", adapter->Luid.Info.NetLuidIndex);
    printf("luid IfType: %u\n", adapter->Luid.Info.IfType);
    wifaces[i].index = adapter->IfIndex;
    wifaces[i].mtu = adapter->Mtu;

    if (adapter->OperStatus != 1)
    {
      wifaces[i].up = 0;
      wifaces[i].addrs_cnt = 0;
      goto loopend;
    }

    wifaces[i].up = 1;
    wifaces[i].addrs_cnt = addrs_count(adapter);
    wifaces[i].addrs = wmalloc(wifaces[i].addrs_cnt * sizeof(struct wifa));

    addr_idx = 0;

    if (adapter->FirstUnicastAddress)
    {
      get_addrs(
        (IP_ADAPTER_UNICAST_ADDRESS *)adapter->FirstUnicastAddress,
        &wifaces[i], &addr_idx);
    }

    //if (adapter->FirstMulticastAddress)
    //{
    //  get_addrs(
    //    (IP_ADAPTER_UNICAST_ADDRESS_LH *)adapter->FirstMulticastAddress,
    //    &wifaces[i], &addr_idx);
    //  wifaces[i].flags |= W_IF_MULTICAST;
    //}
    //
    //if (adapter->FirstAnycastAddress)
    //{
    //  get_addrs(
    //    (IP_ADAPTER_UNICAST_ADDRESS_LH *)adapter->FirstAnycastAddress,
    //    &wifaces[i], &addr_idx);
    //  wifaces[i].flags |= W_IF_MULTICAST;
    //}

loopend:
    adapter_details.InterfaceLuid.Value = 0;
    adapter_details.InterfaceIndex = adapter->IfIndex;
    retval = GetIfEntry2(&adapter_details);
    if (retval != ERROR_SUCCESS)
    {
      printf("GetIfEntry2 failed failed (0x%x)\n", retval);
    }

    wifaces[i].type = convert_access_type(adapter_details.AccessType);

    i += 1;
    adapter = adapter->Next;
  }

  *cnt = adapt_cnt;
  free(adapters);

  return wifaces;
}

static enum wkrtsrc convert_proto_type(int winapi_proto_type)
{
  // TODO: How should be KRT_SRC_BIRD & KRT_SRC_KERNEL set?
  switch (winapi_proto_type)
  {
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

char ipstr[16];
char luidstr[256];

struct wrtentry* win_rt_scan(int ipv, int *cnt)
{
  printf("win_rt_scan called\n");
  ADDRESS_FAMILY family = AF_INET;
  if (ipv == 6)
  {
    family = AF_INET6;
  }

  DWORD retval;
  struct wrtentry *rt_entries;
  MIB_IPFORWARD_TABLE2 *routes = NULL;
  MIB_IPFORWARD_ROW2 *route;
  int idx;

  retval = GetIpForwardTable2(family, &routes);
  if (retval != ERROR_SUCCESS)
  {
    printf("GetIpForwardTable2 failed (0x%x)\n", retval);
    return;
  }

  *cnt = routes->NumEntries;
  rt_entries = (struct wrtentry *)wmalloc(*cnt * sizeof(struct wrtentry));
  printf("Routes count %d\n", *cnt);


  int real_count = 0;
  for (idx = 0; idx < *cnt; idx++)
  {
    route = routes->Table + idx;

    if (route->InterfaceLuid.Info.IfType == 0 ||
        route->DestinationPrefix.PrefixLength > 32 ||
        !(route->Protocol >= 1 && route->Protocol <= 14))
    {
      continue;
    }

    printf("GetIpForwardTable2 LUID: %l64x\n", route->InterfaceLuid.Value);
    printf("luid Reserved: %u\n", route->InterfaceLuid.Info.Reserved);
    printf("luid NetLuidIndex: %u\n", route->InterfaceLuid.Info.NetLuidIndex);
    printf("luid IfType: %u\n", route->InterfaceLuid.Info.IfType);
    printf("Route origin %lu\n", route->Origin);
    printf("Route loopback %lu\n", route->Loopback);
    printf("Route protocol %lu\n", route->Protocol);

    rt_entries[idx].luid = route->InterfaceLuid.Value;
    rt_entries[idx].src = convert_proto_type(route->Protocol);
    rt_entries[idx].metric = route->Metric;
    if (family == AF_INET6)
    {
    }
    else
    {
      rt_entries[idx].next_hop = route->NextHop.Ipv4.sin_addr.S_un.S_addr;
      printf("IPV4: (%lu) %s\n",
        rt_entries[idx].next_hop, inet_ntoa((route->NextHop.Ipv4.sin_addr)));
    }

    MIB_IPNET_ROW2 ipnet;
    ipnet.InterfaceLuid = route->InterfaceLuid;
    ipnet.Address.Ipv4 = route->NextHop.Ipv4;
    printf("ADDR: %lu\n", ipnet.Address.Ipv4.sin_addr.S_un.S_addr);
    retval = GetIpNetEntry2(&ipnet);
    if (retval != ERROR_SUCCESS)
    {
      printf("GetIpNetEntry2 failed (0x%x)\n", retval);
    }

    real_count += 1;
  }
  *cnt = real_count;

  int fuck;
  MIB_IPNET_TABLE2 *ipnet_table = NULL;
  retval = GetIpNetTable2(AF_INET, &ipnet_table);
  printf("GetIpNetTable2 result: 0x%x\n", retval);

  for (fuck = 0; fuck < ipnet_table->NumEntries; fuck++)
  {
    printf("  luid: %lx\n", ipnet_table->Table[fuck].InterfaceLuid.Value);
    printf("  ip hton: (%lu) %s\n",
      ipnet_table->Table[fuck].Address.Ipv4.sin_addr.S_un.S_addr,
      (inet_ntoa(ipnet_table->Table[fuck].Address.Ipv4.sin_addr)));
  }

  FreeMibTable(routes);

  return rt_entries;
}

void win_rt_delete(int dest_pxlen, int dest_prefix, int next_hop,
  unsigned long long luid)
{
  MIB_IPFORWARD_ROW2 entry;
  entry.InterfaceLuid.Value = luid;
  entry.DestinationPrefix.PrefixLength = dest_pxlen;
  entry.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
  entry.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = dest_prefix;
  entry.NextHop.Ipv4.sin_family = AF_INET;
  entry.NextHop.Ipv4.sin_addr.S_un.S_addr = next_hop;

  int ret = DeleteIpForwardEntry2(&entry);
  printf("DeleteIpForwardEntry2 retval 0x%x\n", ret);
}
