// SPDX-License-Identifier: GPL-3.0
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <error.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/un.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "xdp_switch_common.h"

#define STR(__x) #__x
#define XSTR(__x) STR(__x)
#define MAX_TOKEN	40
#define MAX_LINE	(4 * (MAX_TOKEN + 1))
#define MAX_IF		16

#define MAP_EGRESS	0
#define MAP_TX		1
#define MAPS_MAX	2

struct rule {
	struct rule *next;
	__be32 saddr;
};

struct if_status {
	struct rule *list;
	int rule_nr;
};

struct xdp_status {
	int ctr_socket;
	int cl_socket;
	FILE *cl_file;
	int cpu_nr;
	int rx_ports[MAX_IF];
	int rx_nr;
	int tx_ports[MAX_IF];
	int tx_nr;
	struct if_status if_status[MAX_IF];
	int maps[MAPS_MAX];
	int prog_fd;
	struct bpf_object *obj;
	bool interrupted;
	bool cleanup;
	bool use_stdio;
};

#define __file(__x, __file) (__x->use_stdio ? __file : __x->cl_file)
#define srv_out(...) fprintf(__file(global_status, stdout), __VA_ARGS__)
#define srv_err(...) fprintf(__file(global_status, stderr), __VA_ARGS__)

struct xdp_status *global_status;

static void sigint_handler(int signum)
{
	if (signum == SIGINT && global_status)
		global_status->interrupted = true;
}

void __if_stats(struct xdp_status *xdp_status, int id)
{
	struct if_status *ifs = &xdp_status->if_status[id];
	struct egress_entry entry[xdp_status->cpu_nr];
	unsigned long drop_pkts = 0, drop_bytes = 0;
	unsigned long rx_pkts = 0, rx_bytes = 0;
	struct egress_key key;
	struct rule *rule;
	int i;

	key.ifindex = xdp_status->rx_ports[id];
	for (rule = ifs->list; rule; rule = rule->next) {
		key.saddr = rule->saddr;
		if (bpf_map_lookup_elem(xdp_status->maps[MAP_EGRESS], &key,
		    entry)) {
			srv_err("no stats for rule %x %x\n", key.saddr,
			        key.ifindex);
			continue;
		}

		for (i = 0; i < xdp_status->cpu_nr; ++i) {
			rx_pkts += entry[i].pkts;
			rx_bytes += entry[i].bytes;
		}
	}

	key.saddr = 0;
	if (bpf_map_lookup_elem(xdp_status->maps[MAP_EGRESS], &key, entry)) {
		srv_err("no stats for rule %x %x\n", key.saddr, key.ifindex);
	} else {
		for (i = 0; i < xdp_status->cpu_nr; ++i) {
			drop_pkts = entry[i].pkts;
			drop_bytes = entry[i].pkts;
		}
	}
	srv_out("rx %lu:%lu drop %lu:%lu\n", rx_pkts, rx_bytes, drop_pkts,
		drop_bytes);
}

void __if_detach(struct xdp_status *xdp_status, int id)
{
	struct rule *rule, *next;
	struct egress_key key;
	int i;

	key.ifindex = xdp_status->rx_ports[id];
	for (rule = xdp_status->if_status[id].list; rule; rule = next) {
		key.saddr = rule->saddr;
		if (bpf_map_delete_elem(xdp_status->maps[MAP_EGRESS], &key)) {
			srv_err("can't delete rule %x:%x %d %s\n",
			        key.ifindex, key.saddr, errno, strerror(errno));
		}
		next = rule->next;
		free(rule);
	}
	xdp_status->if_status[id].list = NULL;

	key.saddr = 0;
	if (bpf_map_delete_elem(xdp_status->maps[MAP_EGRESS], &key)) {
		srv_err("can't delete stats for if %x %d:%s\n",
		        key.ifindex, errno, strerror(errno));
	}
	bpf_set_link_xdp_fd(global_status->rx_ports[id], -1, 0);

	for (i = id; i + 1 < MAX_IF; ++i) {
		xdp_status->if_status[i] = xdp_status->if_status[i + 1];
		xdp_status->rx_ports[i] = xdp_status->rx_ports[i + 1];
	}

	srv_out(" switch program detached from interface %d id %d\n",
		key.ifindex, id);
	xdp_status->rx_nr--;
}

void init(struct xdp_status *xdp_status)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
		.file		= "xdp_switch.o",
	};
	struct sockaddr_un addr;
	struct bpf_map *map;

	bzero(xdp_status, sizeof(*xdp_status));
	xdp_status->cl_socket = -1;
	xdp_status->ctr_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (xdp_status->ctr_socket == -1)
		error(1, 0, "socket error");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "xdp_dump_switch_ctl", sizeof(addr.sun_path)-1);
	unlink(addr.sun_path);

	if (bind(xdp_status->ctr_socket, (struct sockaddr*)&addr,
		 sizeof(addr)) == -1)
		error(1, 0, "bind error");

	if (listen(xdp_status->ctr_socket, 5) == -1)
		error(1, 0, "listen error");

	if (bpf_prog_load_xattr(&prog_load_attr, &xdp_status->obj,
				&xdp_status->prog_fd))
		error(1, errno, "can't load file %s", prog_load_attr.file);

	map = bpf_object__find_map_by_name(xdp_status->obj, "egress_map");
	if (!map)
		error(1, errno, "can't load egress_map");
	xdp_status->maps[MAP_EGRESS] = bpf_map__fd(map);

	map = bpf_object__find_map_by_name(xdp_status->obj, "tx_port");
	if (!map)
		error(1, errno, "can't load tx_port");
	xdp_status->maps[MAP_TX] = bpf_map__fd(map);

	xdp_status->cpu_nr = sysconf(_SC_NPROCESSORS_CONF);
	xdp_status->cleanup = true;
	xdp_status->interrupted = false;
	global_status = xdp_status;
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, sigint_handler);
}

int __lookup_if_by_name(const int *list, const char *name, int *ifindex)
{
	int id;

	*ifindex = if_nametoindex(name);
	if (!*ifindex) {
		fprintf(stderr, "Can't find interface %s\n", name);
		return -1;
	}

	for (id = 0; id < MAX_IF && list[id]; ++id) {
		if (list[id] == *ifindex)
			return id;
	}
	return -1;
}

void if_attach(struct xdp_status *xdp_status, const char *name)
{
	struct egress_entry entry[xdp_status->cpu_nr];
	struct egress_key key;
	int id;

	if (xdp_status->rx_nr == MAX_IF) {
		srv_err("already attached max interfaces %d\n", MAX_IF);
		return;
	}

	id = __lookup_if_by_name(xdp_status->rx_ports, name, &key.ifindex);
	if (id != -1) {
		srv_err("interface %s:%d already attached in pos %d\n",
		        name, key.ifindex, id);
		return;
	}
	if (!key.ifindex)
		return;

	key.saddr = 0;
	bzero(entry, sizeof(entry));
	if (bpf_map_update_elem(xdp_status->maps[MAP_EGRESS], &key, entry,
				BPF_ANY)) {
		srv_err("can't init stats for interface %s:%d: %d:%s\n",
		        name, key.ifindex, errno, strerror(errno));
		return;
	}
	if (bpf_set_link_xdp_fd(key.ifindex, xdp_status->prog_fd, 0) < 0) {
		srv_err("can't attach xdp program to interface %s:%d: "
		        "%d:%s\n", name, key.ifindex, errno, strerror(errno));
		return;
	}
	srv_out(" switch program attached to interface %s:%d id %d\n",
		name, key.ifindex, xdp_status->rx_nr);
	xdp_status->if_status[xdp_status->rx_nr].list = NULL;
	xdp_status->rx_ports[xdp_status->rx_nr] = key.ifindex;
	xdp_status->rx_nr++;
}

int if_stats(struct xdp_status *xdp_status, const char *name)
{
	int id, ifindex;

	if (!xdp_status->rx_nr) {
		srv_err("no attached interface\n");
		return -1;
	}

	id = __lookup_if_by_name(xdp_status->rx_ports, name, &ifindex);
	if (id == -1) {
		if (ifindex)
			srv_err("interface %s:%d not attached\n",name, ifindex);
		return -1;
	}
	__if_stats(xdp_status, id);
	return id;
}

void if_detach(struct xdp_status *xdp_status, const char *name)
{
	int id = if_stats(xdp_status, name);

	if (id >= 0)
		__if_detach(xdp_status, id);
}

struct rule *___rule_lookup(struct xdp_status *xdp_status, int id,
			    const struct egress_key *key)
{
	struct rule *rule, *prev = xdp_status->if_status[id].list;

	for (rule = xdp_status->if_status[id].list; rule; rule = rule->next) {
		if (rule->saddr == key->saddr)
			return prev;
		prev = rule;
	}
	return NULL;
}

struct rule *__rule_lookup(struct xdp_status *xdp_status, const char *in_dev,
			   const char *saddr, int *id, struct egress_key *key)
{
	*id = -1;
	if (inet_pton(AF_INET, saddr, &key->saddr) != 1) {
		srv_err("invalid addrss %s\n", saddr);
		return NULL;
	}
	if (!xdp_status->rx_nr) {
		srv_err("no attached interface\n");
		return NULL;
	}
	*id = __lookup_if_by_name(xdp_status->rx_ports, in_dev, &key->ifindex);
	if (*id == -1) {
		if (key->ifindex)
			srv_err("interface %s:%d not attached\n",
				in_dev, key->ifindex);
		return NULL;
	}

	return ___rule_lookup(xdp_status, *id, key);
}

void rule_add(struct xdp_status *xdp_status, const char *in_dev,
	      const char *saddr, const char *out_dev)
{
	struct egress_entry entry[xdp_status->cpu_nr];
	struct egress_key key;
	struct rule *rule;
	int id, i;

	rule = __rule_lookup(xdp_status, in_dev, saddr, &id, &key);
	if (rule) {
		srv_err("Rule %x:%x already exists\n", key.ifindex, key.saddr);
		return;
	}
	if (id == -1)
		return;

	bzero(entry, sizeof(entry));
	entry[0].ifindex = if_nametoindex(out_dev);
	for (i = 1; i < xdp_status->cpu_nr; i++)
		entry[i].ifindex = entry[0].ifindex;
	if (!entry[0].ifindex) {
		srv_err("Can't find egress interface %s\n", out_dev);
		return;
	}

	if (bpf_map_update_elem(xdp_status->maps[MAP_TX], &entry[0].ifindex,
				&entry[0].ifindex, BPF_ANY)) {
		srv_err("can't add tx port %s:%d %d:%s\n", out_dev,
		        entry[0].ifindex, errno, strerror(errno));
		return;
	}

	if (bpf_map_update_elem(xdp_status->maps[MAP_EGRESS], &key, entry,
	                        BPF_ANY)) {
		srv_err("Can't add rule %x:%x %d:%s\n", key.ifindex,
		        key.saddr, errno, strerror(errno));
		return;
	}

	rule = calloc(1, sizeof(struct rule));
	if (!rule) {
		srv_err("Can't alloc rule %x:%x\n", key.ifindex, key.saddr);
		return;
	}
	rule->saddr = key.saddr;
	rule->next = xdp_status->if_status[id].list;
	xdp_status->if_status[id].list = rule;
	xdp_status->if_status[id].rule_nr++;
	srv_out("added rule %x:%x -> %x, if rule cnt %d\n", key.ifindex,
		key.saddr, entry[0].ifindex, xdp_status->if_status[id].rule_nr);
}

void rule_del(struct xdp_status *xdp_status, const char *in_dev,
	      const char *saddr)
{
	struct rule *prev, *rule;
	struct egress_key key;
	int id;

	prev = __rule_lookup(xdp_status, in_dev, saddr, &id, &key);
	if (!prev) {
		if (id != -1)
			srv_err("Can't find rule %x:%x\n", key.ifindex,
				key.saddr);
		return;
	}
	if (!prev->next) {
		srv_err("internal error: bad lookup!?!\n");
		return;
	}

	rule = prev->next;
	key.ifindex = xdp_status->rx_ports[id];
	key.saddr = rule->saddr;
	if (bpf_map_delete_elem(xdp_status->maps[MAP_EGRESS], &key)) {
		srv_err("Can't delete rule %x:%x %d:%s\n", key.ifindex,
		        key.saddr, errno, strerror(errno));
		return;
	}

	xdp_status->if_status[id].rule_nr--;
	prev->next = rule->next;
	free(rule);
	srv_out("delered rule %x:%x, if rule cnt %d\n", key.ifindex,
		key.saddr, xdp_status->if_status[id].rule_nr);
}

void cleanup(struct xdp_status *xdp_status)
{
	int id;

	if (!xdp_status->cleanup)
		return;

	xdp_status->use_stdio = true;
	for (id = MAX_IF - 1; id >= 0; --id) {
		if (!xdp_status->rx_ports[id])
			continue;

		__if_stats(xdp_status, id);
		__if_detach(xdp_status, id);
	}
}

bool process_line(struct xdp_status *xdp_status, bool use_stdio)
{
	char tokens[4][MAX_TOKEN + 1];
	char line[MAX_LINE];
	int ret, ntoken, i;

	for (i = 0; i < MAX_LINE - 1; i++) {
		ret = read(use_stdio ? 0 : xdp_status->cl_socket, &line[i], 1);
		if (ret <= 0)
			return false;
		if (line[i] == '\n')
			break;
	}

	line[i]=0;
	ntoken = sscanf(line,"%"XSTR(MAX_TOKEN)"s %"XSTR(MAX_TOKEN)"s "
			    "%"XSTR(MAX_TOKEN)"s %"XSTR(MAX_TOKEN)"s",
			    tokens[0], tokens[1],
			    tokens[2], tokens[3]);
	if (ntoken < 1)
		return true;

	xdp_status->use_stdio = use_stdio;
	if (!strcmp(tokens[0], "quit")) {
		xdp_status->interrupted = true;
	} else if (!strcmp(tokens[0], "attach")) {
		if (ntoken != 2) {
			srv_err("syntax: attach <device>\n");
			return true;
		}
		if_attach(xdp_status, tokens[1]);
	} else if (!strcmp(tokens[0], "detach")) {
		if (ntoken != 2) {
			srv_err("syntax: detach <device>\n");
			return true;
		}
		if_detach(xdp_status, tokens[1]);
	} else if (!strcmp(tokens[0], "stats")) {
		if (ntoken != 2) {
			srv_err("syntax: stats <device>\n");
			return true;
		}
		if_stats(xdp_status, tokens[1]);
	} else if (!strcmp(tokens[0], "add")) {
		if (ntoken != 4) {
			srv_err("syntax: add <in dev> <ip> <out dev>\n");
			return true;
		}
		rule_add(xdp_status, tokens[1], tokens[2], tokens[3]);
	} else if (!strcmp(tokens[0], "del")) {
		if (ntoken != 3) {
			srv_err("syntax: del <in dev> <ip>\n");
			return true;
		}
		rule_del(xdp_status, tokens[1], tokens[2]);
	} else {
		srv_out("unknown command %s\n", tokens[0]);
	}

	fflush(__file(xdp_status, stdout));
	return true;
}

int main(int argc, char *argv[])
{
	struct xdp_status xdp_status;
	int max_fd, ret;
	fd_set rfds;

	init(&xdp_status);

	write(1, ">> ", 3);
	while (!xdp_status.interrupted) {

		FD_ZERO(&rfds);
		FD_SET(0, &rfds);
		if (xdp_status.cl_socket != -1) {
			FD_SET(xdp_status.cl_socket, &rfds);
			max_fd = xdp_status.cl_socket;
		} else {
			FD_SET(xdp_status.ctr_socket, &rfds);
			max_fd = xdp_status.ctr_socket;
		}

		ret = select(max_fd + 1, &rfds, NULL, NULL, NULL);
		if (ret == -1) {
			perror("select");
			continue;
		}

		if (FD_ISSET(0, &rfds)) {
			if (!process_line(&xdp_status, true))
				xdp_status.interrupted = true;
			write(1, ">> ", 3);
		} else if (FD_ISSET(xdp_status.cl_socket, &rfds)) {
			if (!process_line(&xdp_status, false)) {
				fclose(xdp_status.cl_file);
				xdp_status.cl_socket = -1;
			}
		} else if (FD_ISSET(xdp_status.ctr_socket, &rfds)) {
			xdp_status.cl_socket = accept(xdp_status.ctr_socket,
						      NULL, NULL);
			if (xdp_status.cl_socket == -1) {
				perror("accept");
				continue;
			}
			xdp_status.cl_file = fdopen(xdp_status.cl_socket, "a+");
			if (!xdp_status.cl_file) {
				perror("fdopen");
				fclose(xdp_status.cl_file);
				xdp_status.cl_socket = -1;
				continue;
			}
		}
	}

	cleanup(&xdp_status);
	return 0;
}