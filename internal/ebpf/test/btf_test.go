// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"testing"

	ebpf "github.com/shun159/vrftrace2/internal/ebpf"
)

func TestFuncProto1(t *testing.T) {
	var f ebpf.BtfFuncProto

	btf, err := ebpf.LoadVmlinuxBtf()
	if err != nil {
		t.Errorf("LoadVmlinuxBtf() should return err with nil")
	}

	for id := 0; true; id++ {
		btf_type := btf.BtfTypeById(id)

		if !btf_type.IsFunc() {
			continue
		}

		f = btf.BtfFuncProto(btf_type, id)

		// I choose "mctp_route_add" as test sample because the function receives
		// a pointer of struct, typedef-ed scalar value and scalar value.
		if f.Name == "mctp_route_add" {
			break
		}
	}

	if f.Vargs[0] != "mctp_dev" {
		t.Errorf("the first argument should be a pointer of struct mctp_dev")
	}

	if f.Vargs[1] != "mctp_eid_t" {
		t.Errorf("the second argument should be mctp_eid_t")
	}

	if f.Vargs[2] != "unsigned int" {
		t.Errorf("the third argument should be an unsigned int")
	}
}
