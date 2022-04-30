// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package vrft

/*
#include <stdlib.h>
#include "libvrft.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

const ATTACH_RESULT_FMT = "\rAttaching program (total: %d, succeeded: %d, failed: %d)"

var maxArgPos = 5
var targetStructs = []string{
	"vr_packet",
	"sk_buff",
}
var progNames = []string{}
var progDb = make(map[string]*bpf.BPFProg)

func CreateKprobeModule() string {
	name := C.CString("")
	ret := C.deploy_kprobe_module(&name)
	defer C.free(unsafe.Pointer(name))

	if ret != 0 {
		log.Fatalf("Failed to create kprobe module")
	}

	return C.GoString(name)
}

func initBPFProgs() {
	for _, st := range targetStructs {
		for i := 1; i <= maxArgPos; i++ {
			name := strings.Join([]string{st, strconv.Itoa(i)}, "")
			progNames = append(progNames, name)
		}
	}
}

func bpfModCreate(filename string) (*bpf.Module, error) {
	if bpfmod, err := bpf.NewModuleFromFile(filename); err != nil {
		return nil, err
	} else {
		return bpfmod, nil
	}
}

func updateProgDb(bpfmod *bpf.Module) error {
	for _, progname := range progNames {
		if prog, err := bpfmod.GetProgram(progname); err != nil {
			return err
		} else {
			progDb[progname] = prog
		}
	}
	return nil
}

func bpfProgCreate(bpfmod *bpf.Module) error {
	if err := bpfmod.BPFLoadObject(); err != nil {
		return err
	} else {
		return updateProgDb(bpfmod)
	}
}

func attachKprobe(symbol, st_name string, pos int64) error {
	prog_name := fmt.Sprintf("%s%d", st_name, pos)
	if prog, ok := progDb[prog_name]; ok {
		if link, err := prog.AttachKprobe(symbol); err != nil || link == nil {
			return errors.New("Attach kprobe failed: %s")
		}
	} else {
		return errors.New("symbol doesn't exist: %s")
	}
	return nil
}

func attachKprobes(sym_data *SymbolData) error {
	var succeed int
	var failed int
	var total int
	var err error

	for _, st_name := range targetStructs {
		total = total + len(sym_data.SymList[st_name])
	}

	for _, st_name := range targetStructs {
		for symbol, pos := range sym_data.SymList[st_name] {
			if err := attachKprobe(symbol, st_name, pos); err != nil {
				failed = failed + 1
				err = errors.New("Attach kprobe failed")
				break
			}
			succeed = succeed + 1
			fmt.Printf(ATTACH_RESULT_FMT, total, succeed, failed)
		}
	}
	fmt.Println("")

	return err
}

func createPerfbuf(bpfmod *bpf.Module, sym_data *SymbolData) (*bpf.PerfBuffer, error) {
	var eventsChannel chan []byte
	var lostChannel chan uint64

	// channel for events (and lost events)
	eventsChannel = make(chan []byte, 1000)
	lostChannel = make(chan uint64)

	go handleEvent(eventsChannel, sym_data)

	p, err := bpfmod.InitPerfBuf("events", eventsChannel, lostChannel, 1024)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func InitBPF(sym_data *SymbolData) (*bpf.PerfBuffer, error) {
	initBPFProgs()

	mod_filename := CreateKprobeModule()
	bpfmod, err := bpfModCreate(mod_filename)
	if err != nil {
		return nil, err
	}

	if err := bpfProgCreate(bpfmod); err != nil {
		return nil, err
	}

	if err := attachKprobes(sym_data); err != nil {
		return nil, err
	}

	perf, err := createPerfbuf(bpfmod, sym_data)
	if err != nil {
		return nil, err
	}

	return perf, nil
}
