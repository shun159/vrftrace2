// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"testing"

	ebpf "github.com/shun159/vrftrace2/internal/ebpf"
)

func TestInitSymsDb(t *testing.T) {
	args := ebpf.SymbolDbArgs{
		Btf: map[string][]string{
			"vr_packet": {
				"/tmp/vrouter.btf",
			},
			"sk_buff": {
				"/sys/kernel/btf/vmlinux",
				"/tmp/vrouter.btf",
			},
		},
	}

	symsdb, err := ebpf.InitSymbolDb(&args)
	if err != nil {
		t.Errorf("err: %+v\n", err)
	}

	if _, ok := symsdb.Pos2Func["sk_buff"]; !ok {
		t.Errorf("Key sk_buff should be exist")
	}

	pos, ok := symsdb.Pos2Func["sk_buff"]["skb_gro_receive"]

	if !ok {
		t.Errorf("skb_gro_receive should be exist")
	}

	if pos != 1 {
		t.Errorf("skb_gro_receive should be received a pointer of sk_buff at 1st arg")
	}
}
