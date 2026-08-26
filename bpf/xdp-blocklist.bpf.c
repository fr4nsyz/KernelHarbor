// go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

char LICENSE[] SEC("license") = "GPL";

struct lpm_key_v4 {
	__u32 prefixlen;
	__u8 data[4];
};

struct lpm_key_v6 {
	__u32 prefixlen;
	__u8 data[16];
};

#define BLOCKLIST_MAX_ENTRIES (1 << 16)

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, BLOCKLIST_MAX_ENTRIES);
	__type(key, struct lpm_key_v4);
	__type(value, __u8);
} blocklist_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, BLOCKLIST_MAX_ENTRIES);
	__type(key, struct lpm_key_v6);
	__type(value, __u8);
} blocklist_v6 SEC(".maps");

static __always_inline int handle_ipv4(void *p, void *data_end)
{
	struct iphdr *ip = p;

	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	struct lpm_key_v4 key = { .prefixlen = 32 };
	__builtin_memcpy(key.data, &ip->saddr, sizeof(key.data));

	if (bpf_map_lookup_elem(&blocklist_v4, &key))
		return XDP_DROP;

	return XDP_PASS;
}

static __always_inline int handle_ipv6(void *p, void *data_end)
{
	struct ipv6hdr *ip6 = p;

	if ((void *)(ip6 + 1) > data_end)
		return XDP_PASS;

	struct lpm_key_v6 key = { .prefixlen = 128 };
	__builtin_memcpy(key.data, &ip6->saddr, sizeof(key.data));

	if (bpf_map_lookup_elem(&blocklist_v6, &key))
		return XDP_DROP;

	return XDP_PASS;
}

SEC("xdp")
int xdp_blocklist(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = (void *)data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__be16 proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_IP))
		return handle_ipv4(eth + 1, data_end);
	if (proto == bpf_htons(ETH_P_IPV6))
		return handle_ipv6(eth + 1, data_end);

	return XDP_PASS;
}
