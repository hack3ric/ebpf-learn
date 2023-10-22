#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u8);
  __type(value, __u32);
  __uint(max_entries, 256);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} my_map SEC(".maps");

#define KEY_EGRESS 0
#define KEY_INGRESS 1

__u32 incrctr(__u8 key) {
  __u32* ctr_ptr = bpf_map_lookup_elem(&my_map, &key);
  if (ctr_ptr) {
    return __sync_add_and_fetch(ctr_ptr, 1);
  }

  __u32 ctr = 1;
  long result = bpf_map_update_elem(&my_map, &key, &ctr, BPF_NOEXIST);
  if (result) {
    __bpf_printk("Failed to create new counter for key %d: %d", key, result);
    return 0;
  }
  return ctr;
}

__u32 readctr(__u8 key) {
  __u32* ctr_ptr = bpf_map_lookup_elem(&my_map, &key);
  return ctr_ptr ? *ctr_ptr : 0;
}

SEC("egress")
int egress_handler(struct __sk_buff* skb) {
  __bpf_printk("egress recv'd:\t%d\t%d", incrctr(KEY_EGRESS), readctr(KEY_INGRESS));
  return TC_ACT_OK;
}

SEC("ingress")
int ingress_handler(struct __sk_buff* skb) {
  __bpf_printk("ingress recv'd:\t%d\t%d", incrctr(KEY_INGRESS), readctr(KEY_EGRESS));
  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
