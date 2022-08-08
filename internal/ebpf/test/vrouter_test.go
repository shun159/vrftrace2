// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"testing"

	ebpf "github.com/shun159/vrftrace2/internal/ebpf"
)

func TestDumpInterfaces(t *testing.T) {
	if !ebpf.IsVrouterKmodLoaded() {
		t.Skip("only run if vrouter.ko loaded on test setup")
	}

	vifs, err := ebpf.DumpVrInterfaces()

	if err != nil {
		t.Errorf("err should be nil")
	}

	if len(*vifs) < 2 {
		t.Errorf("should be returned a list of vif object have two or more elements")
	}
}
