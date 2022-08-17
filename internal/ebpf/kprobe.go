// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"log"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	progress "github.com/schollz/progressbar/v3"
)

var progNames = []string{}

const KprobeBPFProg = "/tmp/vrftrace_kprobe.bpf.o"
const maxArgPos = 5
const ATTACH_RESULT_FMT = "\rAttaching program (total: %d, succeeded: %d)"

type VrfraceKprobeSpec struct {
	btf_file    string
	symdb       SymbolDb
	module      *bpf.Module
	prog2func   map[string][]string
	print_state *printFgraphState
}

type KprobePerfEvent struct {
	PacketId    uint64
	Tstamp      uint64
	Faddr       uint64
	Fname       string
	ProcessorId uint32
	IsReturn    bool
}

func (spec VrfraceKprobeSpec) handleKprobeEvent(event chan []byte) {
	for b := range event {
		perf := KprobePerfEvent{}
		perf.PacketId = binary.LittleEndian.Uint64(b[0:8])
		perf.Tstamp = binary.LittleEndian.Uint64(b[8:16])
		perf.Faddr = binary.LittleEndian.Uint64(b[16:24])
		perf.ProcessorId = binary.LittleEndian.Uint32(b[24:28])

		//binary.LittleEndian.Uint32(b[28:31])

		is_return := b[31:32][0]
		perf.IsReturn = false

		if is_return == 1 {
			perf.IsReturn = true
		}

		fname, err := spec.symdb.FindSymByFaddr(perf.Faddr)
		if err != nil {
			fmt.Printf("err: %v", err)
		}

		perf.Fname = fname
		spec.print_state.printKprobeEvent(perf)
	}
}

/*
 * Create BPF module.
 * This function receives an absolute path for the btf (e,g: /sys/kernel/btf/vmlinux)
 */
func (spec *VrfraceKprobeSpec) createModule(btf_file string) error {
	module_args := bpf.NewModuleArgs{
		BTFObjPath: btf_file,
		BPFObjPath: KprobeBPFProg,
	}

	if bpfmod, err := bpf.NewModuleFromFileArgs(module_args); err != nil {
		return err
	} else {
		spec.module = bpfmod
		return nil
	}
}

func (spec *VrfraceKprobeSpec) loadObject() error {
	if err := spec.module.BPFLoadObject(); err != nil {
		return err
	}

	return nil
}

/*
 * Map function name to program name
 */
func (spec *VrfraceKprobeSpec) mapProgName2Func() error {
	prog2func := map[string][]string{}

	for st_name, pos2func := range spec.symdb.Pos2Func {
		for fname, pos := range pos2func {
			for _, prefix := range []string{"kprobe", "kretprobe"} {
				prog_name := fmt.Sprintf("%s_%s%d", prefix, st_name, pos)
				if _, ok := prog2func[prog_name]; !ok {
					prog2func[prog_name] = []string{}
				}
				prog2func[prog_name] = append(prog2func[prog_name], fname)
			}
		}
	}

	spec.prog2func = prog2func
	return nil
}

/*
 * Map program name to bpf_prog
 */
func (spec *VrfraceKprobeSpec) attachKprobe() error {
	var prog *bpf.BPFProg
	var succeed int

	iter := spec.module.Iterator()
	prog = iter.NextProgram()
	total := spec.symdb.CountPos2Func()
	bar := progress.Default(int64(total))

	for prog != nil {
		prog_name := prog.GetName()
		fnames, prog2func_found := spec.prog2func[prog_name]
		if prog2func_found {
			for _, fname := range fnames {
				var link *bpf.BPFLink
				var err error

				if strings.HasPrefix(prog_name, "kretprobe") {
					link, err = prog.AttachKretprobe(fname)
				} else {
					link, err = prog.AttachKprobe(fname)
				}

				if err != nil {
					fmt.Printf("Failed to attach program: %s fname: %s abort!\n", prog_name, fname)
					return err
				}

				if link == nil {
					fmt.Printf("Failed to attach program: %s skipped\n", prog_name)
					continue
				}

				succeed = succeed + 1
				bar.Add(1)
			}
		}

		prog = iter.NextProgram()
	}

	fmt.Println("")

	return nil
}

func (spec *VrfraceKprobeSpec) createIfaceMap() error {
	m, err := spec.module.GetMap("iface_map")
	if err != nil {
		return err
	}

	ifaces, err := DumpVrInterfaces()
	if err != nil {
		return err
	}

	log.Printf("Filter events with %d interfaces on vrouter kernel...\n", len(*ifaces))

	for _, vif := range *ifaces {
		os_idx := uint32(vif.OsIdx)
		vif_idx := uint32(vif.Idx)
		err := m.Update(unsafe.Pointer(&os_idx), unsafe.Pointer(&vif_idx))
		if err != nil {
			return err
		}
	}

	return nil
}

func (spec *VrfraceKprobeSpec) initPerfMap() (*bpf.PerfBuffer, error) {
	var event_chan chan []byte
	var lost_chan chan uint64

	// channels for events receive from the BPF program
	event_chan = make(chan []byte, 256)
	lost_chan = make(chan uint64, 16)

	go spec.handleKprobeEvent(event_chan)

	p, err := spec.module.InitPerfBuf("events", event_chan, lost_chan, 1024)
	if err != nil {
		return nil, err
	}

	return p, nil

}

func InitKprobe(btf_file string, args SymbolDbArgs) (*bpf.PerfBuffer, error) {
	symdb, err := InitSymbolDb(&args)
	if err != nil {
		return nil, err
	}

	spec := VrfraceKprobeSpec{}
	spec.print_state = &printFgraphState{0}
	spec.symdb = *symdb

	if err := spec.createModule(btf_file); err != nil {
		return nil, err
	}

	if err := spec.loadObject(); err != nil {
		return nil, err
	}

	if err := spec.mapProgName2Func(); err != nil {
		return nil, err
	}

	if err := spec.createIfaceMap(); err != nil {
		return nil, err
	}

	if err := spec.attachKprobe(); err != nil {
		return nil, err
	}

	p, err := spec.initPerfMap()

	if err != nil {
		return nil, err
	}

	printKprobeHeader()

	return p, nil
}
