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

#define shift_ptr(type, ret, nhptr, data_end) ({ \
  type* result = nhptr; \
  nhptr += sizeof(type); \
  if (nhptr > data_end) {  \
    return ret; \
  } \
  result; \
})

#define shift_ptr_decl(type, name, nhptr, skb) \
  type* name = shift_ptr(type, TC_ACT_OK, nhptr, (void*)(long)skb->data_end);

static inline int handle_ipv4(struct iphdr* ipv4, void** nhptr, struct __sk_buff* skb) {
  if (ipv4->protocol != IPPROTO_ICMP) return -1;

  shift_ptr_decl(struct icmphdr, icmp, *nhptr, skb);
  __bpf_printk("%pI4 -> %pI4", &ipv4->saddr, &ipv4->daddr);
  __bpf_printk("type %d, code %d", icmp->type, icmp->code);

  // We only modify echo request
  if (icmp->type != ICMP_ECHO) return -1;

  __u16 l4_len = bpf_ntohs(ipv4->tot_len) - (ipv4->ihl << 2);
  __bpf_printk("l4_len = %d", l4_len);
  __u16 sport = 11451;
  __u16 dport = 41919;

  // Change L4 header from ICMP to UDP
  *nhptr -= sizeof(struct icmphdr);
  shift_ptr_decl(struct udphdr, udp, *nhptr, skb);
  udp->source = bpf_htons(sport);
  udp->dest = bpf_htons(dport);
  udp->len = bpf_htons(l4_len);
  udp->check = 0;

  // TODO: calculate UDP checksum
  __sum16 udp_csum = 0;
  udp->check = udp_csum;

  __u8 old_protocol = ipv4->protocol;
  ipv4->protocol = IPPROTO_UDP;
  bpf_l3_csum_replace(skb, (__u32)ipv4 - skb->data + offsetof(struct iphdr, check),
    bpf_htons(old_protocol), bpf_htons(ipv4->protocol), 2);

  return 0;
}

SEC("classifier")
int change_l4(struct __sk_buff* skb) {
  void* nhptr = (void*)(long)skb->data;

  shift_ptr_decl(struct ethhdr, eth, nhptr, skb);
  switch (bpf_ntohs(eth->h_proto)) {
    case 0x0800: /* IPv4 */ {
      shift_ptr_decl(struct iphdr, ipv4, nhptr, skb);
      if (handle_ipv4(ipv4, &nhptr, skb)) return TC_ACT_OK;
      break;
    }
    case 0x86dd: /* IPv6 */ {
      shift_ptr_decl(struct ipv6hdr, ipv6, nhptr, skb);
      break;
    }
    default: // We don't know about/process this packet
      return TC_ACT_OK;
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
