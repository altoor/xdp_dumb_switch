#ifndef XDP_SWITCH_COMMON_H_
#define XDP_SWITCH_COMMON_H_

struct egress_key {
	__be32 saddr;
	__s32 ifindex;
};

struct egress_entry {
	__u64 pkts;
	__u64 bytes;
	__s32 ifindex;
};

#endif