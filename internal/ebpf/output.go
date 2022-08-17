// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"fmt"
	"math"
)

type printFgraphState struct {
	indent int
}

func printKprobeHeader() {
	fmt.Printf("%-20s %3.3s %32.32s\n", "Timestamp", "CPU", "Function")
}

func (p *printFgraphState) printKprobeEvent(event KprobePerfEvent) {
	if !event.IsReturn {
		s := fmt.Sprintf("%-*s%s() {", p.indent*2, "", event.Fname)
		fmt.Printf("%-20d %03d %-64.64s\n", event.Tstamp, event.ProcessorId, s)

		if p.indent != math.MaxUint32 {
			p.indent += 1
		}
	} else {
		if p.indent != 0 {
			p.indent -= 1
		}

		s := fmt.Sprintf("%-*s}", p.indent*2, "")
		fmt.Printf("%-20d %03d %-64.64s\n", event.Tstamp, event.ProcessorId, s)
	}
}
