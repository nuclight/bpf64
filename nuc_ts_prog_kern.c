#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common/parsing_helpers.h"

#include "nuc_ts_common_kern_user.h"

#define TCPOPT_TS_KIND 8  /* Timestamp option has Kind=8 */ 
#define TCPOPT_TS_LEN 10  /* and length 10, per RFC 1323 */

#define LOG bpf_printk

/* map to count errors */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
} xdp_errstats_map SEC(".maps");

char _license[] SEC("license") = "GPL";

static void rec2stat(__u32 error)
{
	long *value;

	value = bpf_map_lookup_elem(&xdp_errstats_map, &error);
	if (value)
		*value += 1;
}

static int parse_ipv4(void **nh_pos, void *data_end, __u64 *l4_off)
{
	struct iphdr *iph = *nh_pos;
	LOG("parse_ipv4: nh_pos=%p\n", *nh_pos);
	if (iph + 1 > data_end) {
		LOG("parse_ipv4: iph+1=%p\n", iph+1);
		rec2stat(STAT_IPHDRSHORT);
		return 0;
	}
	if (*nh_pos + (0x0fff & 1 + bpf_ntohs(iph->tot_len)) > data_end) {
		LOG("parse_ipv4: tot_len=%d\n", bpf_ntohs(iph->tot_len));
		rec2stat(STAT_IPTOTSHORT);
		return 0;
	}
	if (iph->ihl < 5) {
		LOG("parse_ipv4: ihl=%d\n", iph->ihl);
		rec2stat(STAT_IPHDRSHORT);
		return 0;
	}

	*l4_off = 20 + 4*(iph->ihl - 5);
	LOG("parse_ipv4: l4_off:=%d\n", *l4_off);
	if (*nh_pos + *l4_off > data_end) {
		rec2stat(STAT_IPHDRSHORT);
		return 0;
	}
	return iph->protocol;
}

static int parse_ipv6(void **nh_pos, void *data_end, __u64 *l4_off)
{
	struct ipv6hdr *ip6h = *nh_pos;
	if (ip6h + 1 > data_end) {
		rec2stat(STAT_IPHDRSHORT);
		return 0;
	}
	if (*nh_pos + (0xefff & 1 + bpf_ntohs(ip6h->payload_len)) > data_end) {
		rec2stat(STAT_IPTOTSHORT);
		return 0;
	}

	*l4_off = sizeof(struct ipv6hdr);
	__u8 next_hdr_type = ip6h->nexthdr;
	struct ipv6_opt_hdr *hdr = *nh_pos + *l4_off;

	for (int i = 0; i < 6; ++i) {
		if (hdr + 1 > data_end) {
			rec2stat(STAT_IP6EXTHDRSHORT);
			return 0;
		}

		switch (next_hdr_type) {
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_MH:
			*l4_off += (hdr->hdrlen + 1) * 8;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_AH:
			*l4_off += (hdr->hdrlen + 2) * 4;
			next_hdr_type = hdr->nexthdr;
			break;
		case IPPROTO_FRAGMENT:
			*l4_off += 8;
			next_hdr_type = hdr->nexthdr;
			break;
		default:
			/* Found a header that is not an IPv6 extension header */
			LOG("parse_ipv6: l4_off:=%d next=%d\n", *l4_off, next_hdr_type);
			return next_hdr_type;
		}
	}

	LOG("parse_ipv6: l4_off:=%d next_hdr_type=%d\n", *l4_off, next_hdr_type);
	return next_hdr_type;
}

/* -1 format err, 0 untouched, 1 modified */
static int process_tcp(void **nh_pos, __u64 l4_off, void *data_end)
{
	__u64 size, old_ofs, changed = 0, open, cur = 0;
	__u64 optkind, optlen, err = STAT_VERIFIERHAPPY;

	*nh_pos += l4_off & 0xff;
	LOG("process_tcp: nh_pos:=%p l4_off=%d\n", *nh_pos, l4_off);
	struct tcphdr *tcph = *nh_pos;
	if (tcph + 1 > data_end) {
		LOG("process_tcp: tcph+1=%p\n", tcph+1);
		err = STAT_TCPSHORT;
		goto err_past_end;
	}

	size = 4*tcph->doff;
	LOG("process_tcp: initial size=%d\n", size);
	if ((*nh_pos + size > data_end)) {
		LOG("process_tcp: nh_pos=%p +size=%p\n", *nh_pos, *nh_pos + size);
		err = STAT_TCPSHORT;
		goto err_past_end;
	}
	if (size < 20) {
		err = STAT_TCPINVALID;
		goto err_past_end;
	}
	*nh_pos += 20;
	size -= 20;;

	if (size == 0)	/* no options - pass as-is */
		return 0;

	__u32 sum;
	unsigned short old;
	void *chgptr;

/* make verifier happy */
#define ACCESS_OPT_PTR(setptr, offs)	do {			\
		if ((offs) > 39) goto err_past_end;		\
		(setptr) = (void*)(*nh_pos + (offs));		\
		if ((setptr) + 1 > data_end)			\
			goto err_past_end;			\
	} while(0)
#define ACCESS_OPT_PTR_SHORT(setptr, offs)	do {		\
		if ((offs) > 38) goto err_past_end;		\
		(setptr) = (void*)(*nh_pos + (offs));		\
		if ((setptr) + 2 > data_end)			\
			goto err_past_end;			\
	} while(0)
#define ACCESS_OPT_BYTE(setvar, offs)	do {			\
		void *tmp;					\
		ACCESS_OPT_PTR(tmp, offs);			\
		(setvar) = *( (__u8*)tmp );			\
	} while(0)

	while (cur < size && cur < 40) {
		LOG("while {");
		barrier_var(cur);
		open = 261;	/* just marker to be in disasm */
		ACCESS_OPT_BYTE(optkind, cur);
		LOG("optkind=%d\n", optkind);

		/* Single-byte options */
		if (optkind == 0)	/* End of Options */
			break;
		if (optkind == 1) {	/* NOP */
			cur++;
			continue;
		}

		/* Kind and length bytes options */
		if (cur+1 >= size) {
			LOG("cur+1 >= size: %d+1 >= %d\n", cur, size);
			err = STAT_TCPOPTOVERFLOW;
			goto err_past_end;
		}

		ACCESS_OPT_BYTE(optlen, cur+1);
		LOG("optlen=%d\n", optlen);
		if (optlen < 2) {
			err = STAT_TCPINVALID;
			goto err_past_end;
		}
		if (optlen > size - cur)
			goto unclosed;

		if (optkind == TCPOPT_TS_KIND) {
			if (optlen != TCPOPT_TS_LEN || changed) {
				err = STAT_TCPINVALID;
				goto err_past_end;
			}

			/* increment TSval */
			old_ofs = cur+4; // FIXME word align from tcp start
			LOG("old_ofs=%d\n", old_ofs);
			ACCESS_OPT_PTR_SHORT(chgptr, old_ofs);
			LOG("chgptr=%p\n", chgptr);
			old = bpf_ntohs(*(unsigned short *)chgptr);
			ACCESS_OPT_PTR(chgptr, cur+5);
			*((__u8*)chgptr) += 1;
			changed = 1;
		}

		/* Skip to next option */
		cur += optlen;
		open = 0;
	}
	if (open)
		goto unclosed;

	/* Update checksum incrementally per RFC 1141 */
	if (changed) {
		ACCESS_OPT_PTR_SHORT(chgptr, old_ofs);
		sum = old + (~bpf_ntohs(*(unsigned short *)chgptr) & 0xffff);
		sum += bpf_ntohs(tcph->check);
		sum = (sum & 0xffff) + (sum>>16);
		LOG("changing cksum to htons(%x)\n", sum);
		tcph->check = bpf_htons(sum + (sum>>16));
		
		return 1;
	}

	return 0;

unclosed:
	err = STAT_TCPOPTOVERFLOW;

err_past_end:
	rec2stat(err);
	return -1;

}

SEC("xdp")
int xdp_tcp_timestamp_incr(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int rc = XDP_DROP;
	__u16 h_proto;
	__u64 nh_off;
	__u32 ipproto;
	__u64 l4_off;
	void *nh_pos;

	LOG("got packet: ctx=%p data=%p data_end=%p\n", ctx, data, data_end);
	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) {
		rec2stat(STAT_ETHSHORT);
		return rc;
	}

	h_proto = eth->h_proto;

	/* check VLAN tag; could be repeated to support double-tagged VLAN */
	if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end) {
			rec2stat(STAT_VLANSHORT);
			return rc;
		}
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	nh_pos = data + nh_off;
	if (h_proto == bpf_htons(ETH_P_IP))
		ipproto = parse_ipv4(&nh_pos, data_end, &l4_off);
	else if (h_proto == bpf_htons(ETH_P_IPV6))
		ipproto = parse_ipv6(&nh_pos, data_end, &l4_off);
	else {
		rec2stat(STAT_NONIP);
		return rc;
	}

	if (ipproto != IPPROTO_TCP) {
		/* pass non-TCP untouched */
		rec2stat(STAT_NONTCP);
		rc = XDP_PASS;
	} else {
		int done = process_tcp(&nh_pos, l4_off, data_end);
		if (done == -1) {
			rc = XDP_DROP;
		} else if (done == 0) {
			rec2stat(STAT_NONTSTAMP);
			rc = XDP_PASS;
		} else {
			rec2stat(STAT_TS_INCREMENTED);
			rc = XDP_PASS;
		}
	}

	return rc;
}
