
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

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

struct wiface* win_if_scan(int ipv, int *cnt)
{
  printf("win_if_scan called\n");

  ULONG size = 15000;
  DWORD retval = ERROR_SUCCESS;
  ULONG family = AF_INET;
  if (ipv == 6)
    family = AF_INET6;

  IP_ADAPTER_ADDRESSES *adapter, *adapters;
  struct wiface *wifaces;
  int i, adapt_cnt, addr_idx;

  adapters = wmalloc(size);

  retval = GetAdaptersAddresses(AF_INET,
    GAA_FLAG_INCLUDE_PREFIX |
    GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    adapters,
    &size);

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
    wifaces[i].index = adapter->IfIndex;
    wifaces[i].mtu = adapter->Mtu;
    wifaces[i].up = adapter->OperStatus;
    if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
    {
      wifaces[i].flags |= W_IF_LOOPBACK;
    }


    wifaces[i].addrs_cnt = addrs_count(adapter);
    wifaces[i].addrs = wmalloc(wifaces[i].addrs_cnt * sizeof(struct wifa));

    addr_idx = 0;

    if (adapter->FirstUnicastAddress)
    {
      get_addrs(
        (IP_ADAPTER_UNICAST_ADDRESS *)adapter->FirstUnicastAddress,
        &wifaces[i], &addr_idx);
      wifaces[i].flags |= W_IF_MULTICAST;
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

struct wrtentry* win_rt_scan(int ipv, int *cnt)
{
  printf("win_rt_scan called\n");
  ADDRESS_FAMILY family = AF_INET;
  if (ipv == 6)
  {
    family = AF_INET6;
  }

  struct wrtentry *rt_entries;
  MIB_IPFORWARD_TABLE2 *table = NULL;
  int idx;

  GetIpForwardTable2(family, &table);
  *cnt = table->NumEntries;
  rt_entries = (struct wrtentry *)wmalloc(*cnt * sizeof(struct wrtentry));

  for (idx = 0; idx , idx < *cnt; idx++)
  {
    printf("LUID: %lu\n", table->Table[idx].InterfaceLuid.Value);
    rt_entries[idx].luid = table->Table[idx].InterfaceLuid.Value;
    rt_entries[idx].src = convert_proto_type(table->Table[idx].Protocol);
    rt_entries[idx].metric = table->Table[idx].Metric;
    if (family == AF_INET6)
    {
    }
    else
    {
      rt_entries[idx].next_hop = table->Table[idx].NextHop.Ipv4.sin_addr.S_un.S_addr;
    }


  }


  FreeMibTable(table);

  return rt_entries;
}
