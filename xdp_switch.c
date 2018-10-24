/* Copyright (C) 2017 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

#include "xdp_switch_common.h"

/* forwarding map */
struct bpf_map_def SEC("maps") egress_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct egress_key),
	.value_size = sizeof(struct egress_entry),
	.max_entries = 20000,
};

/* redirect map */
struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};

/* Parse IPV4 packet to get SRC, DST IP and protocol */
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end,
			     __be32 *src, __be32 *dest)
{
	struct iphdr *iph = data + nh_off;

	if (iph + 1 > data_end)
		return 0;

	*src = iph->saddr;
	*dest = iph->daddr;
	return iph->protocol;
}

int xdp_router_ipv4_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct egress_entry *entry;
	struct ethhdr *eth = data;
	struct egress_key key;
	__be32 dest_ip = 0;
	__u16 h_proto;
	__u64 nh_off;
	int ipproto;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		goto drop;

	/* parse vlan */
	h_proto = eth->h_proto;
	if (h_proto == __constant_htons(ETH_P_8021Q) ||
	    h_proto == __constant_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			goto drop;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto != __constant_htons(ETH_P_IP))
		goto drop;

	key.saddr = 0;
	ipproto = parse_ipv4(data, nh_off, data_end, &key.saddr, &dest_ip);
	if (!ipproto)
		goto drop;

	key.ifindex = ctx->ingress_ifindex;
	entry = bpf_map_lookup_elem(&egress_map, &key);
	if (!entry)
		goto drop;

	entry->pkts++;
	entry->bytes += ctx->data_end - ctx->data;
	return bpf_redirect_map(&tx_port, entry->ifindex, 0);

drop:
	key.ifindex = ctx->ingress_ifindex;
	key.saddr = 0;
	entry = bpf_map_lookup_elem(&egress_map, &key);
	if (entry) {
		entry->pkts++;
		entry->bytes += ctx->data_end - ctx->data;
	}
	return XDP_DROP;
}

char _license[] __attribute__ ((section("license"), used)) = "GPL";