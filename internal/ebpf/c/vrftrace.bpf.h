// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

#include <stdint.h>
#include <linux/types.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/*
 * ============================================
 *  tf-vrouter packet structure
 * ============================================
 */
struct vr_packet;

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
 *  The perf event structure
 * ============================================
 */

#define SK_BUFF 1
#define VR_PACKET 2

struct vrft_event {
  uint64_t packet_id;
  // UNIX timestamp in nano seconds precision
  uint64_t tstamp;
  // An instance pointer of the function
  uint64_t faddr;
  // The processor id where the function is running
  uint32_t processor_id;
  // align to 8
  uint8_t pad1[3];
  // Is this kretprobe?
  uint8_t is_return;

  // pad field for future use.
  uint8_t _pad__[8];
} __attribute__((aligned(8)));

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(key_size, sizeof(uint32_t));
  __uint(value_size, sizeof(uint32_t));
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, uint32_t);
  __type(value, uint32_t);
} iface_map SEC(".maps");

#define __noinline __attribute__((noinline))

static uint64_t get_func_ip(void *ctx);

static __always_inline int
handle_sk_buff(struct pt_regs *ctx, uint8_t is_return, struct sk_buff *skb)
{
  uint32_t skb_iif, vr_skb_iif, *t_vr_skb_iif;
  uint32_t dev_ifindex, vr_dev_ifindex, *t_vr_dev_ifindex;
  struct vrft_event e = {0};

  skb_iif = (uint32_t)BPF_CORE_READ(skb, skb_iif);
  dev_ifindex = (uint32_t)BPF_CORE_READ(skb, dev, ifindex);

  t_vr_skb_iif = bpf_map_lookup_elem(&iface_map, &skb_iif);
  t_vr_dev_ifindex = bpf_map_lookup_elem(&iface_map, &dev_ifindex);

  if (t_vr_dev_ifindex == NULL)
    vr_dev_ifindex = 0;
  else
    __builtin_memcpy_inline(&vr_dev_ifindex, t_vr_dev_ifindex,
                            sizeof(uint32_t));

  if (t_vr_skb_iif == NULL)
    vr_skb_iif = 0;
  else
    __builtin_memcpy_inline(&vr_skb_iif, t_vr_skb_iif, sizeof(uint32_t));

  if (vr_skb_iif < 1 && vr_dev_ifindex < 1)
    return 0;

  e.packet_id = (uint64_t)skb;
  e.tstamp = bpf_ktime_get_ns();
  e.faddr = PT_REGS_IP((struct pt_regs *)ctx) - 1;
  e.processor_id = bpf_get_smp_processor_id();
  e.is_return = is_return;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

  return 0;
}

static __always_inline int
handle_vr_packet(struct pt_regs *ctx, uint8_t is_return, struct vr_packet *pkt)
{
  struct vrft_event e = {0};

  e.packet_id = (uint64_t)pkt;
  e.tstamp = bpf_ktime_get_ns();
  e.faddr = get_func_ip(ctx);
  e.processor_id = bpf_get_smp_processor_id();
  e.is_return = is_return;

  bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

  return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
unsigned int _version SEC("version") = 0xFFFFFFFE;
