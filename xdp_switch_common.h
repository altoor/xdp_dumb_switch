#ifndef XDP_SWITCH_COMMON_H_
#define XDP_SWITCH_COMMON_H_

struct egress_key {
	__be32 saddr;
	int ifindex;
};

struct egress_entry {
	unsigned long pkts;
	unsigned long bytes;
	int ifindex;
};

#endif