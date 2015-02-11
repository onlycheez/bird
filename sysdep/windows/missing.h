

#include <stdint.h>

// bits/in.h (linux/in.h)
#define IP_RECVTTL   12
#define IP_PMTUDISC_DONT   0       /* Never send DF frames.  */
#define IP_MTU_DISCOVER    10
#define IPV6_PMTUDISC_DONT        0       /* Never send DF frames.  */
#define IPV6_MTU_DISCOVER 23

//asm-generic/socket.h
#define SO_PRIORITY     12
#define SO_REUSEPORT    15

// netinet/icmp6.h
#define ICMP6_FILTER 1
#define ICMP6_FILTER_SETBLOCKALL(filterp) \
    memset (filterp, 0xFF, sizeof (struct icmp6_filter));
#define ICMP6_FILTER_SETPASS(type, filterp) \
     ((((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31))))


// netinet/icmp6.h (linux/icmpv6.h)
struct icmp6_filter
  {
    uint32_t icmp6_filt[8];
  };
