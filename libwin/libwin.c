
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>

void win_if_scan(void)
{
  ULONG size = 10 * sizeof(IP_ADAPTER_ADDRESSES);
  IP_ADAPTER_ADDRESSES *addresses = (IP_ADAPTER_ADDRESSES *)malloc(size);

  GetAdaptersAddresses(AF_INET,
    GAA_FLAG_INCLUDE_ALL_INTERFACES |
    GAA_FLAG_INCLUDE_PREFIX |
    GAA_FLAG_SKIP_DNS_SERVER,
    NULL,
    addresses,
    &size);
}
