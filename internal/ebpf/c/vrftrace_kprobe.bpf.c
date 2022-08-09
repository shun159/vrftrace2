// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

#include <linux/ptrace.h>

#include "vrftrace.bpf.h"

static __inline uint64_t
get_func_ip(void *ctx)
{
	return PT_REGS_IP((struct pt_regs *)ctx) - 1;
}

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

KPROBE(sk_buff, handle_sk_buff)
KPROBE(vr_packet, handle_vr_packet)
