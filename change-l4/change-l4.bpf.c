#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_END (ETH_HLEN)
#define IPV4_END (ETH_END + sizeof(struct iphdr))
#define IPV6_END (ETH_END + sizeof(struct ipv6hdr))
#define IPV4_UDP_END (IPV4_END + sizeof(struct udphdr))
#define IPV6_UDP_END (IPV6_END + sizeof(struct udphdr))

#define check_decl(type, name, off, skb, ret)                           \
  type* name = ({                                                       \
    type* ptr = (void*)(size_t)skb->data + off;                         \
    if ((size_t)ptr + sizeof(type) > (size_t)skb->data_end) return ret; \
    ptr;                                                                \
  })

#define check_decl_unspec(type, name, off, skb) \
  check_decl(type, name, off, skb, TC_ACT_UNSPEC)

#define try(x)                  \
  ({                            \
    int result = x;             \
    if (!result) return result; \
  })

static void update_csum(__u16* csum, __s32 delta) {
  __u32 new_csum = (__u16) ~*csum + delta;
  for (int i = 0; i < 3; i++) {
    __u16 hi = new_csum >> 16, lo = new_csum & 0xffff;
    if (!hi) break;
    new_csum = hi + lo;
  }
  *csum = ~new_csum;
}

static void update_csum_ipv4_pseudo(__u16* csum, struct iphdr* ipv4) {
  __u32 saddr = bpf_ntohl(ipv4->saddr);
  __u32 daddr = bpf_ntohl(ipv4->daddr);
  __u16 l4_len = bpf_ntohs(ipv4->tot_len) - (ipv4->ihl << 2);

  update_csum(csum, saddr >> 16);
  update_csum(csum, saddr & 0xffff);
  update_csum(csum, daddr >> 16);
  update_csum(csum, daddr & 0xffff);
  update_csum(csum, ipv4->protocol);
  update_csum(csum, l4_len);
}

static void update_csum_ipv6_pseudo(__u16* csum, struct ipv6hdr* ipv6) {
  for (int i = 0; i < 8; i++) {
    update_csum(csum, bpf_ntohs(ipv6->saddr.in6_u.u6_addr16[i]));
    update_csum(csum, bpf_ntohs(ipv6->daddr.in6_u.u6_addr16[i]));
  }
  update_csum(csum, bpf_ntohs(ipv6->payload_len));
  update_csum(csum, ipv6->nexthdr);
}

static void update_csum_udp_header(__u16* csum, struct udphdr* udp) {
  update_csum(csum, bpf_ntohs(udp->source));
  update_csum(csum, bpf_ntohs(udp->dest));
  update_csum(csum, bpf_ntohs(udp->len));
}

static void update_csum_data(struct __sk_buff* skb, __u16* csum, __u32 off) {
  __u16* data = (void*)(size_t)skb->data + off;
  for (int i = 0; i < ETH_DATA_LEN / 2; i++) {
    if ((size_t)(data + i + 1) > (size_t)skb->data_end) break;
    update_csum(csum, bpf_ntohs(data[i]));
  }
}

static int handle_ipv4(struct __sk_buff* skb) {
  check_decl_unspec(struct iphdr, ipv4, ETH_END, skb);
  if (ipv4->protocol != IPPROTO_ICMP) return TC_ACT_OK;
  check_decl_unspec(struct icmphdr, icmp, IPV4_END, skb);

  // We only modify echo request
  if (icmp->type != ICMP_ECHO) return TC_ACT_OK;

  __u16 l4_len = bpf_ntohs(ipv4->tot_len) - (ipv4->ihl << 2);
  __u16 sport = 11451, dport = 41919;

  // Change L4 header from ICMP to UDP
  check_decl_unspec(struct udphdr, udp, IPV4_END, skb);
  udp->source = bpf_htons(sport);
  udp->dest = bpf_htons(dport);
  udp->len = bpf_htons(l4_len);

  __u8 old_protocol = ipv4->protocol;
  ipv4->protocol = IPPROTO_UDP;

  __u16 udp_csum = 0xffff;
  update_csum_ipv4_pseudo(&udp_csum, ipv4);
  update_csum_udp_header(&udp_csum, udp);
  update_csum_data(skb, &udp_csum, IPV4_UDP_END);
  udp->check = bpf_htons(udp_csum);

  bpf_l3_csum_replace(
      skb, (__u32)(size_t)ipv4 - skb->data + offsetof(struct iphdr, check),
      bpf_htons(old_protocol), bpf_htons(ipv4->protocol), 2);

  return TC_ACT_OK;
}

static int handle_ipv6(struct __sk_buff* skb) {
  check_decl_unspec(struct ipv6hdr, ipv6, ETH_END, skb);
  if (ipv6->nexthdr != IPPROTO_ICMPV6) return TC_ACT_OK;
  check_decl_unspec(struct icmp6hdr, icmpv6, IPV6_END, skb);

  // We only modify echo request
  if (icmpv6->icmp6_type != ICMPV6_ECHO_REQUEST) return TC_ACT_OK;
  __u16 l4_len = bpf_ntohs(ipv6->payload_len);
  __u16 sport = 11451, dport = 41919;

  // Change L4 header from ICMP to UDP
  check_decl_unspec(struct udphdr, udp, IPV6_END, skb);
  udp->source = bpf_htons(sport);
  udp->dest = bpf_htons(dport);
  udp->len = bpf_htons(l4_len);

  __u8 old_protocol = ipv6->nexthdr;
  ipv6->nexthdr = IPPROTO_UDP;

  __u16 udp_csum = 0xffff;
  update_csum_ipv6_pseudo(&udp_csum, ipv6);
  update_csum_udp_header(&udp_csum, udp);
  update_csum_data(skb, &udp_csum, IPV6_UDP_END);
  udp->check = bpf_htons(udp_csum);

  // IPv6 has no checksum

  return TC_ACT_OK;
}

SEC("classifier")
int change_l4(struct __sk_buff* skb) {
  check_decl_unspec(struct ethhdr, eth, 0, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case ETH_P_IP:
      try(handle_ipv4(skb));
      break;
    case ETH_P_IPV6:
      try(handle_ipv6(skb));
      break;
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
