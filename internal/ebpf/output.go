// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import "fmt"

func printKprobeHeader() {
	fmt.Printf("%-20s %3.3s %32.32s\n", "Timestamp", "CPU", "Function")
}

func printKprobeEvent(event KprobePerfEvent) {
	fmt.Printf("%-20d %3.3d %32.32s\n", event.Tstamp, event.ProcessorId, event.Fname)
}
