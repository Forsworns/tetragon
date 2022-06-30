// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __SKB_H__
#define __SKB_H__

struct skb_type {
	__u32 hash;
	__u32 len;
	__u32 priority;
	__u32 mark;
	__u32 saddr;
	__u32 daddr;
	__u32 sport;
	__u32 dport;
	__u32 proto;
	__u32 secpath_len;
	__u32 secpath_olen;
};

/* set_event_from_skb(skb)
 *
 * Populate the event args with the SKB 5-tuple when supported. Currently,
 * only supports IPv4 with TCP/UDP.
 */
static inline __attribute__((unused)) int
set_event_from_skb(struct skb_type *event, struct sk_buff *skb)
{
	unsigned char *skb_head = 0;
	u16 l3_off;

	bpf_core_read(&skb_head, sizeof(skb_head), &skb->head);
	bpf_core_read(&l3_off, sizeof(l3_off), &skb->network_header);

	struct iphdr *ip = (struct iphdr *)(skb_head + l3_off);
	u8 iphdr_byte0;
	bpf_core_read(&iphdr_byte0, 1, ip);

	u8 ip_ver = iphdr_byte0 >> 4;
	if (ip_ver == 4) { // IPv4
		u8 v4_prot;
		bpf_core_read(&v4_prot, 1, &ip->protocol);

		event->proto = v4_prot;

		bpf_core_read(&event->saddr, sizeof(event->saddr), &ip->saddr);
		bpf_core_read(&event->daddr, sizeof(event->daddr), &ip->daddr);
		typeof(skb->transport_header) l4_off;
		bpf_core_read(&l4_off, sizeof(l4_off), &skb->transport_header);
		if (v4_prot == IPPROTO_TCP) { // TCP
			struct tcphdr *tcp =
				(struct tcphdr *)(skb_head + l4_off);
			bpf_core_read(&event->sport, sizeof(event->sport),
				      &tcp->source);
			bpf_core_read(&event->dport, sizeof(event->dport),
				      &tcp->dest);
		} else if (v4_prot == IPPROTO_UDP) { // UDP
			struct udphdr *udp =
				(struct udphdr *)(skb_head + l4_off);
			bpf_core_read(&event->sport, sizeof(event->sport),
				      &udp->source);
			bpf_core_read(&event->dport, sizeof(event->dport),
				      &udp->dest);
		}

		if (bpf_core_field_exists(skb->active_extensions)) {
			struct sec_path *sp;
			struct skb_ext *ext;
			u64 offset;

#define SKB_EXT_SEC_PATH 1 // TBD do this with BTF
			bpf_core_read(&ext, sizeof(ext), &skb->extensions);
			if (ext) {
				bpf_core_read(&offset, sizeof(offset),
					      &ext->offset[SKB_EXT_SEC_PATH]);
				sp = (void *)ext + (offset << 3);

				bpf_core_read(&event->secpath_len,
					      sizeof(event->secpath_len),
					      &sp->len);
				bpf_core_read(&event->secpath_olen,
					      sizeof(event->secpath_olen),
					      &sp->olen);
			}
		}
		return 0;
	} else if (ip_ver == 6) {
		return -1;
	}

	// This is not IP, so we don't know how to parse further.
	return -22;
}
#endif // __SKB_H__
