/*
 *	BIRD Internet Routing Daemon -- Linux Multicasting and Network Includes
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <netinet/in.h>
#include <netinet/ip.h>

#define ICMP6_FILTER 1
#define ICMP6_FILTER_SETBLOCKALL(filterp) \
  memset (filterp, 0xFF, sizeof (struct icmp6_filter));
#define ICMP6_FILTER_SETPASS(type, filterp) \
  ((((filterp)->icmp6_filt[(type) >> 5]) &= ~(1 << ((type) & 31))))

struct icmp6_filter
{
  uint32_t icmp6_filt[8];
};

#ifdef IPV6
#define SA_LEN(x) sizeof(struct sockaddr_in6)
#else
#define SA_LEN(x) sizeof(sockaddr)
#endif

/*
 *  Cygwin IPv4 multicast syscalls
 */

#define INIT_MREQ4(maddr,ifa) \
  { .imr_multiaddr = ipa_to_in4(maddr), .imr_interface = ipa_to_in4(ifa->addr->ip) }

static inline int
sk_setup_multicast4(sock *s)
{
  int index = htonl(s->iface->index);
  u8 ttl = s->ttl;
  u8 n = 0;

  /* This defines where should we send _outgoing_ multicasts */
  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_IF, &index, sizeof(index)) < 0)
    ERR("IP_MULTICAST_IF");

  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0)
    ERR("IP_MULTICAST_TTL");

  if (setsockopt(s->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &n, sizeof(n)) < 0)
    ERR("IP_MULTICAST_LOOP");

  return 0;
}

static inline int
sk_join_group4(sock *s, ip_addr maddr)
{
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);

  if (setsockopt(s->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_ADD_MEMBERSHIP");

  return 0;
}

static inline int
sk_leave_group4(sock *s, ip_addr maddr)
{
  struct ip_mreq mr = INIT_MREQ4(maddr, s->iface);

  if (setsockopt(s->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mr, sizeof(mr)) < 0)
    ERR("IP_DROP_MEMBERSHIP");

  return 0;
}

#define CMSG4_SPACE_PKTINFO CMSG_SPACE(sizeof(struct in_pktinfo))
#define CMSG4_SPACE_TTL CMSG_SPACE(sizeof(int))

static inline int
sk_request_cmsg4_pktinfo(sock *s)
{
  int y = 1;

  if (setsockopt(s->fd, IPPROTO_IP, IP_PKTINFO, &y, sizeof(y)) < 0)
    ERR("IP_PKTINFO");

  return 0;
}

static inline int
sk_request_cmsg4_ttl(sock *s)
{
  ERR_MSG("Kernel does not support IPv4 TTL security(request)");

  return 0;
}

static inline void
sk_process_cmsg4_pktinfo(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_PKTINFO)
  {
    struct in_pktinfo *pi = (struct in_pktinfo *) CMSG_DATA(cm);
    s->laddr = ipa_from_in4(pi->ipi_addr);
    s->lifindex = pi->ipi_ifindex;
  }
}

static inline void
sk_process_cmsg4_ttl(sock *s, struct cmsghdr *cm)
{
  if (cm->cmsg_type == IP_TTL)
    s->rcv_ttl = * (int *) CMSG_DATA(cm);
}

static inline void
sk_prepare_cmsgs4(sock *s, struct msghdr *msg, void *cbuf, size_t cbuflen)
{

}

static void
sk_prepare_ip_header(sock *s, void *hdr, int dlen)
{
  struct ip *ip = hdr;

  bzero(ip, 20);

  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = (s->tos < 0) ? 0 : s->tos;
  ip->ip_len = 20 + dlen;
  ip->ip_ttl = (s->ttl < 0) ? 64 : s->ttl;
  ip->ip_p = s->dport;
  ip->ip_src = ipa_to_in4(s->saddr);
  ip->ip_dst = ipa_to_in4(s->daddr);
}

int
sk_set_md5_auth(sock *s, ip_addr a, struct iface *ifa, char *passwd)
{
  ERR_MSG("Kernel does not support TCP MD5 signatures");

  return 0;
}

static inline int
sk_set_min_ttl4(sock *s, int ttl)
{
  ERR_MSG("Kernel does not support IPv4 TTL security");

  return 0;
}

static inline int
sk_set_min_ttl6(sock *s, int ttl)
{
  ERR_MSG("Kernel does not support IPv6 TTL security");
}

static inline int
sk_disable_mtu_disc4(sock *s)
{
  return 0;
}

static inline int
sk_disable_mtu_disc6(sock *s)
{
  return 0;
}

int sk_priority_control = -1;

static inline int
sk_set_priority(sock *s, int prio)
{
  ERR_MSG("Socket priority not supported");
}
