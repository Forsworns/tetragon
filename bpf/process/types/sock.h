// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __SOCK_H__
#define __SOCK_H__

struct sk_type {
	__u16 family;
	__u16 type;
	__u16 protocol;
	__u16 pad;
	__u32 mark;
	__u32 priority;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
};

/* set_event_from_sock(sock)
 *
 * Populate the event args with the sock info.
 */
static inline __attribute__((unused)) void
set_event_from_sock(struct sk_type *event, struct sock *sk)
{
	struct sock_common *common = (struct sock_common *)sk;

	event->family = 0;

	bpf_core_read(&event->family, sizeof(event->family),
		      &common->skc_family);
	bpf_core_read(&event->type, sizeof(event->type), &sk->sk_type);
	bpf_core_read(&event->protocol, sizeof(event->protocol),
		      &sk->sk_protocol);
	bpf_core_read(&event->mark, sizeof(event->mark), &sk->sk_mark);
	bpf_core_read(&event->priority, sizeof(event->priority),
		      &sk->sk_priority);

	bpf_core_read(&event->saddr, sizeof(event->daddr), &common->skc_daddr);
	bpf_core_read(&event->daddr, sizeof(event->saddr),
		      &common->skc_rcv_saddr);
	bpf_core_read(&event->sport, sizeof(event->sport), &common->skc_num);
	bpf_core_read(&event->dport, sizeof(event->dport), &common->skc_dport);
}
#endif // __SOCK_H__
