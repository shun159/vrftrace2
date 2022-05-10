// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

#include <stdint.h>
#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*
 * ============================================
 *  Linux netdev
 * ============================================
 */
// The DEVICE structure.
struct net_device {
	// interface index
	int ifindex;
};

// socket buffer
struct sk_buff {
	// Device we arrived on/are leaving by
	struct net_device *dev;
	// ifindex of device we arrived on
	int skb_iif;
};

/*
 * ============================================
 *  vrouter vr_packet
 * ============================================
 */

// The Virtual Interface structure
struct vr_interface {
	// VRF index the interface belongs to.
	uint16_t vif_vrf;
	// interface index
	uint32_t vif_os_idx;
};

// The nexthop strcture. the structure is similar to ofp_action.
struct vr_nexthop {
	// One of the following:
	// - NH_TYPE_DEAD(0)
	// - NH_TYPE_RCV(1)
	// - NH_TYPE_ENCAP(2)
	// - NH_TYPE_TUNNEL(3)
	// - NH_TYPE_RESOLVE(4)
	// - NH_TYPE_DISCARD(5)
	// - NH_TYPE_COMPOSIT(6)
	// - NH_TYPE_VRF_TRANSLATE(67
	uint8_t nh_type;
};

// The packet structure. the structure is similar to sk_buff.
struct vr_packet {
	// Device we arrived on/are leaving by
	struct vr_interface *vp_if;
	// The nexthop index which packets processed on.
	struct vr_nexthop *vp_nh;
};

struct vrft_event {
	uint64_t packet_id;
	// UNIX timestamp in nano seconds precision
	uint64_t tstamp;
	// An instance pointer of the function
	uint64_t faddr;
	// The processor id where the function is running
	uint32_t processor_id;
	// Is this kretprobe?
	uint8_t is_return;
	// ifindex of device we arrived on
	uint32_t iif;
	// device ifindex
	uint32_t dev_ifindex;
	// pad field for future use.
	uint8_t _pad2[20];
} __attribute__((aligned(8)));

#define __noinline __attribute__((noinline))

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key_size, sizeof(uint32_t));
	__type(value_size, sizeof(uint32_t));
} iface_map SEC(".maps");

#define KPROBE_NUM(ST_NAME, HANDLER_FUNC, NUM)                                 \
	SEC("kprobe/##ST_NAME##NUM")                                           \
	int ST_NAME##NUM(struct pt_regs *ctx)                                  \
	{                                                                      \
		struct ST_NAME *req =                                          \
			(struct ST_NAME *)PT_REGS_PARM##NUM(ctx);              \
		return HANDLER_FUNC(ctx, 0, req);                              \
	}

#define KPROBE(ST_NAME, HANDLER_FUNC)                                          \
	KPROBE_NUM(ST_NAME, HANDLER_FUNC, 1)                                   \
	KPROBE_NUM(ST_NAME, HANDLER_FUNC, 2)                                   \
	KPROBE_NUM(ST_NAME, HANDLER_FUNC, 3)                                   \
	KPROBE_NUM(ST_NAME, HANDLER_FUNC, 4)                                   \
	KPROBE_NUM(ST_NAME, HANDLER_FUNC, 5)

static __always_inline int
handle_sk_buff(struct pt_regs *ctx, uint8_t is_return, struct sk_buff *skb)
{
	uint32_t skb_iif;
	uint32_t dev_ifindex;
	struct vrft_event e = { 0 };

	skb_iif = (uint32_t)BPF_CORE_READ(skb, skb_iif);
	dev_ifindex = (uint32_t)BPF_CORE_READ(skb, dev, ifindex);

	if (skb_iif < 1 && dev_ifindex < 1)
		return 0;

	e.packet_id = (uint64_t)skb;
	e.tstamp = bpf_ktime_get_ns();
	e.faddr = PT_REGS_IP((struct pt_regs *)ctx) - 1;
	e.processor_id = bpf_get_smp_processor_id();
	e.is_return = is_return;
	e.iif = skb_iif;
	e.dev_ifindex = dev_ifindex;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

static __always_inline int
handle_vr_packet(struct pt_regs *ctx, uint8_t is_return, struct vr_packet *pkt)
{
	uint32_t vif_vrf;
	uint32_t dev_ifindex;
	struct vrft_event e = { 0 };

	dev_ifindex = BPF_CORE_READ(pkt, vp_if, vif_os_idx);
	vif_vrf = (uint32_t)BPF_CORE_READ(pkt, vp_if, vif_vrf);

	e.packet_id = (uint64_t)pkt;
	e.tstamp = bpf_ktime_get_ns();
	e.faddr = PT_REGS_IP((struct pt_regs *)ctx) - 1;
	e.processor_id = bpf_get_smp_processor_id();
	e.is_return = is_return;
	e.iif = vif_vrf;
	e.dev_ifindex = dev_ifindex;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

	return 0;
}

KPROBE(sk_buff, handle_sk_buff);
KPROBE(vr_packet, handle_vr_packet);

char LICENSE[] SEC("license") = "Dual BSD/GPL";
unsigned int _version SEC("version") = 0xFFFFFFFE;
