
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

#include <stdio.h>

#include "wstructs.h"

static IP_ADAPTER_ADDRESSES *addresses;
static IP_ADAPTER_ADDRESSES *cur_addr;

void die(const char *msg, ...) __attribute__((noreturn));

LPVOID wmalloc(ULONG size)
{
  void *p = malloc(size);
  if (p)
    return p;
  die("Unable to allocate %d bytes of memory", size);
}

int win_if_update_in_progess(void)
{
  printf("win_if_scan in progress\n");
  return !!addresses;
}

void win_if_scan(int ipv)
{
  printf("win_if_scan called\n");

  ULONG size = 15000;
  DWORD retval = ERROR_SUCCESS;
  ULONG family = AF_INET;
  if (ipv == 6)
    ipv = AF_INET6;

  addresses = wmalloc(size);

  retval = GetAdaptersAddresses(AF_INET,
    GAA_FLAG_INCLUDE_PREFIX |
    GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    addresses,
    &size);

  cur_addr = addresses;
}

struct wiface* win_if_next(void)
{
  if (!cur_addr)
  {
    if (addresses)
    {
      free(addresses);
      addresses = NULL;
    }

    return NULL;
  }

  struct wiface *wif = wmalloc(sizeof(struct wiface));

  wif->name = strdup(cur_addr->AdapterName);
  wif->index = cur_addr->IfIndex;
  wif->mtu = cur_addr->Mtu;
  wif->flags = cur_addr->Flags;
  wif->oper_status = cur_addr->OperStatus;
  wif->is_loopback = (cur_addr->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

  IP_ADAPTER_UNICAST_ADDRESS *address = cur_addr->FirstUnicastAddress;
  if (address)
  {
    SOCKADDR *sockaddr = address->Address.lpSockaddr;
#ifdef IPV6
#else
    printf("address: %s\n", inet_ntoa(((struct sockaddr_in *)sockaddr)->sin_addr));
    wif->ipv4_addr = ((struct sockaddr_in *)sockaddr)->sin_addr.S_un.S_addr;
#endif
    //address = address->Next;
  }

  IP_ADAPTER_PREFIX *prefix = cur_addr->FirstPrefix;
  if (prefix)
  {
    SOCKADDR *sockaddr = prefix->Address.lpSockaddr;
    wif->prefix = ((struct sockaddr_in *)sockaddr)->sin_addr.S_un.S_addr;
    wif->prefix_len = prefix->PrefixLength;
  }

  cur_addr = cur_addr->Next;

  return wif;
}
