#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("classifier")
int change_ttl(struct __sk_buff* skb) {
  __u8 version_ihl;
  bpf_skb_load_bytes(skb, ETH_HLEN, &version_ihl, 1);
  __u8 version = version_ihl >> 4;
  __bpf_printk("IP version %d", version);

  if (version == 4) {
    __u8 ttl = (__u8)bpf_get_prandom_u32();
    __u8 old_ttl;
    bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, ttl), &old_ttl, 1);
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_ttl, ttl, 2);
    bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, ttl), &ttl, 1, 0);
  }

  return BPF_OK;
}

char _license[] SEC("license") = "GPL";
