//go:build ignore

#include <stddef.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
/*
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
*/
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
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} ipv4_count SEC(".maps");

struct parser {
  void *pos;
};

static __always_inline int parse_eth(struct parser *par, void *end,
                                     struct ethhdr **out) {
  // dest, src, EtherType (aka size)
  struct ethhdr *header = par->pos;
  int size = sizeof(*header);
  par->pos += size;
  *out = header;
  return header->h_proto;
}

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct parser parser;
  parser.pos = data;
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
  // Count IPv4 packets.
  struct ethhdr *eth;
  if (parse_eth(&parser, data_end, &eth) == bpf_htons(ETH_P_IP)) {
    __u64 *v4 = bpf_map_lookup_elem(&ipv4_count, &key);
    __u64 new_v4 = 0;
    if (v4) {
      new_v4 = *v4 + 1;
    }
    bpf_map_update_elem(&ipv4_count, &key, &new_v4, BPF_ANY);
  }

  return XDP_PASS;
}

char __license[] SEC("license") = "MPL";
