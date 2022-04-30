// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

#include <bpf/bpf.h>
#include <bpf/btf.h>

const char*
btf_str_by_offset_from_type(const struct btf*, const struct btf_type*);

int
btf_find_pos(const char*, const struct btf*, const char *);

int
deploy_vrouter_btf(char **namep);

int
deploy_kprobe_module(char **namep);
