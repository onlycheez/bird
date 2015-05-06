
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

void win_if_scan(int ipv)
{
  printf("win_if_scan called\n");
  if (addresses)
  {
    printf("win_if_scan in progress\n");
    /* Scan is in progress. To get next interface call win_if_next. */
    return;
  }

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

  printf("retval success %d\n", retval == ERROR_SUCCESS);

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

  IP_ADAPTER_ADDRESSES *address = cur_addr->FirstUnicastAddress;
  while (address)
  {

  }

  cur_addr

  cur_addr = cur_addr->Next;

  return wif;
}
