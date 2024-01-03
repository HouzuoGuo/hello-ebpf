//go:build ignore

#include <stddef.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_size SEC(".maps");

struct {
  // __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 128);
} src_data_len SEC(".maps");

struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __be16 tot_len;
  __be16 id;
  __be16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __sum16 check;
  __be32 saddr;
  __be32 daddr;
};

static __always_inline int parse_addr(struct xdp_md *ctx, __u32 *out_src,
                                      __u16 *out_len) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end) {
    return 0;
  }
  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    return 0;
  }
  struct iphdr *ip = (void *)(eth + 1);
  if ((void *)(ip + 1) > data_end) {
    return 0;
  }
  *out_src = ip->saddr;
  *out_len = ip->tot_len;
  return 1;
}

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  // Count all packets and sum their lengths.
  __u32 key = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
  __u64 new_count = 0;
  if (count) {
    new_count = *count + 1;
  }
  bpf_map_update_elem(&pkt_count, &key, &new_count, BPF_ANY);

  __u64 *size = bpf_map_lookup_elem(&pkt_size, &key);
  __u64 new_size = 0;
  if (size) {
    new_size = *size + (ctx->data_end - ctx->data);
  }
  bpf_map_update_elem(&pkt_size, &key, &new_size, BPF_ANY);

  __u32 src_ip;
  __u16 src_len;
  __u64 new_len = 0;
  if (!parse_addr(ctx, &src_ip, &src_len)) {
    return XDP_PASS;
  }
  __u64 *existing_len = bpf_map_lookup_elem(&src_data_len, &src_ip);
  new_len += src_len;
  if (existing_len) {
    new_len += *existing_len;
  }
  bpf_map_update_elem(&src_data_len, &src_ip, &new_len, BPF_ANY);

  return XDP_PASS;
}

char __license[] SEC("license") = "MPL";
