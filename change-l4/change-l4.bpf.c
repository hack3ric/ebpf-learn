#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define shift_ptr(type, ret, nhptr, data_end) ({ \
  type* result = nhptr; \
  nhptr += sizeof(type); \
  if (nhptr > data_end) {  \
    return ret; \
  } \
  result; \
})

#define shift_ptr_decl(type, name, ret) \
  type* name = shift_ptr(type, ret, nhptr, (void*)(long)skb->data_end);

SEC("classifier")
int change_l4(struct __sk_buff* skb) {
  void* nhptr = (void*)(long)skb->data;

  shift_ptr_decl(struct ethhdr, eth, TC_ACT_OK);
  switch (bpf_ntohs(eth->h_proto)) {
    case 0x0800: /* IPv4 */ {
      shift_ptr_decl(struct iphdr, ipv4, TC_ACT_OK);
      __bpf_printk("%d", bpf_ntohl(ipv4->addrs.saddr));
      break;
    }
    case 0x86dd: /* IPv6 */ {
      break;
    }
    default: // We don't know about/process this packet
      return TC_ACT_OK;
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";
