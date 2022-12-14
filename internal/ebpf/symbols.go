// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const ULLONG_MAX = 0xffffffffffffffff

// https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
const kernel_addr_space = 0x00ffffffffffffff
const available_filter_functions = "/sys/kernel/debug/tracing/available_filter_functions"
const kallsyms = "/proc/kallsyms"

type SymbolDb struct {
	AvailFunc map[string]bool
	FuncAddr  map[uint64]string
	Pos2Func  map[string]map[string]int
}

func (symsdb *SymbolDb) CountPos2Func() int {
	ret := 0

	for _, funcs := range symsdb.Pos2Func {
		ret += len(funcs)
	}

	return ret
}

func (symsdb *SymbolDb) FindSymByFaddr(faddr uint64) (string, error) {
	if fname, ok := symsdb.FuncAddr[faddr-4]; !ok {
		if fname, ok = symsdb.FuncAddr[faddr]; !ok {
			err := fmt.Errorf("%x doesn't exist in kallsyms", faddr)
			return "", err
		}
		return fname, nil
	} else {
		return fname, nil
	}
}

func (symsdb *SymbolDb) IsAvailFilter(fname string) bool {
	if _, ok := symsdb.AvailFunc[fname]; !ok {
		return false
	} else {
		return true
	}
}

func (symsdb *SymbolDb) PopulatePos2Func(args *SymbolDbArgs) error {
	symsdb.Pos2Func = make(map[string]map[string]int)

	for st_name, btf_paths := range args.Btf {
		func_map := map[string]int{}

		for _, btf_path := range btf_paths {
			btf, err := ParseRaw(btf_path)

			if err != nil {
				return err
			}

			for id := 0; true; id++ {
				var f BtfFuncProto

				t := btf.BtfTypeById(id)
				if t == nil {
					break
				}

				if !t.IsFunc() {
					continue
				}

				f = btf.BtfFuncProto(t, id)

				for pos, varg := range f.Vargs {
					switch varg {
					case st_name:
						if symsdb.IsAvailFilter(f.Name) {
							func_map[f.Name] = pos + 1
						}
					default:
						continue
					}

					break
				}
			}
		}

		symsdb.Pos2Func[st_name] = func_map
	}

	return nil
}

func (symsdb *SymbolDb) PopulateKallSyms() error {
	symsdb.FuncAddr = make(map[uint64]string)
	fh, err := os.Open(kallsyms)
	defer fh.Close()

	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		var func_addr string
		var func_name string
		var symbol_type string

		line := scanner.Text()
		fmt.Sscanf(line, "%s %s %s ", &func_addr, &symbol_type, &func_name)
		symbol_type = strings.ToLower(symbol_type)

		// Ignore data symbols
		if symbol_type == "b" ||
			symbol_type == "d" ||
			symbol_type == "r" {
			continue
		}

		// Only add the symbols which are available
		if exist, _ := symsdb.AvailFunc[func_name]; !exist {
			continue
		}

		addr, _ := strconv.ParseUint(func_addr, 16, 64)

		if addr == 0 ||
			addr == ULLONG_MAX ||
			addr < kernel_addr_space {
			continue
		}

		symsdb.FuncAddr[addr] = func_name
	}

	return nil
}

func (symsdb *SymbolDb) PopulateAvailableFunctions() error {
	symsdb.AvailFunc = make(map[string]bool)
	fh, err := os.Open(available_filter_functions)
	defer fh.Close()

	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(fh)
	for scanner.Scan() {
		var func_name string
		line := scanner.Text()
		_, err := fmt.Sscanf(line, "%s ", &func_name)

		if err != nil {
			return err
		}

		symsdb.AvailFunc[func_name] = true
	}

	return nil
}

type SymbolDbArgs struct {
	Btf map[string][]string
}

func InitSymbolDb(args *SymbolDbArgs) (*SymbolDb, error) {
	symsdb := &SymbolDb{}

	if err := symsdb.PopulateAvailableFunctions(); err != nil {
		return nil, err
	}

	if err := symsdb.PopulateKallSyms(); err != nil {
		return nil, err
	}

	if err := symsdb.PopulatePos2Func(args); err != nil {
		return nil, err
	}

	return symsdb, nil
}
