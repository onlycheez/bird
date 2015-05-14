
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

#include <stdio.h>

#include "wstructs.h"

/* GUID length + 2 for parenthesis */
#define GUID_LENGTH 39

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

PSTR narrow_wstr(PCWSTR wstr)
{
  int length = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
  PSTR str = (PSTR)wmalloc(length);
  WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, length, NULL, NULL);
  return str;
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

  PSTR friendly_name = narrow_wstr(cur_addr->FriendlyName);

  int name_len = strlen((const char *)friendly_name) + 2 + GUID_LENGTH;
  wif->name = wmalloc(name_len + 1);
  wif->name[name_len] = '\0';
  snprintf(wif->name, name_len, "%s, %s", friendly_name, cur_addr->AdapterName);

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

  // TODO: free
  //free(friendly_name);

  return wif;
}
