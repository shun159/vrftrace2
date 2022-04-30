package vrft

/*
#include <stdlib.h>
#include "libvrft.h"
*/
import "C"
import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	bpf_helpers "github.com/aquasecurity/libbpfgo/helpers"
)

const vRouterSymList = "/tmp/vrftrace_pkt_func_list.txt"
const vmLinuxSymList = "/tmp/vrftrace_skb_func_list.txt"

type SymbolData struct {
	SymTable     *bpf_helpers.KernelSymbolTable
	SymList      map[string]map[string]int64
	AvailSymbols map[string]bool
}

func CreateVrouterBTF() string {
	name := C.CString("")
	ret := C.deploy_vrouter_btf(&name)
	defer C.free(unsafe.Pointer(name))

	if ret != 0 {
		log.Fatalf("Failed to create BTF file")
	}

	return C.GoString(name)
}

func CreateVrouterSymList(name string) int {
	st_name := C.CString("vr_packet")
	filename := C.CString(vRouterSymList)
	path := C.CString(name)
	btf := C.btf__parse_raw(path)
	defer C.free(unsafe.Pointer(path))
	defer C.free(unsafe.Pointer(st_name))
	defer C.free(unsafe.Pointer(filename))

	ret := C.btf_find_pos(st_name, btf, filename)
	if ret != 0 {
		log.Fatalf("Failed to create symbol list")
	}

	return int(ret)
}

func CreateVMLINUXSymList() int {
	st_name := C.CString("sk_buff")
	filename := C.CString(vmLinuxSymList)
	btf := C.btf__load_vmlinux_btf()
	defer C.free(unsafe.Pointer(st_name))
	defer C.free(unsafe.Pointer(filename))

	ret := C.btf_find_pos(st_name, btf, filename)
	if ret != 0 {
		log.Fatalf("Failed to create symbol list")
	}

	return int(ret)
}

func InitSymbolData() (*SymbolData, error) {
	sym_table, err := bpf_helpers.NewKernelSymbolsMap()
	if err != nil {
		log.Fatalf("Failed to create symbol map: %v", err)
		return nil, err
	}

	sym_data := &SymbolData{}
	sym_data.SymList = make(map[string]map[string]int64)
	sym_data.SymTable = sym_table

	return sym_data, nil
}

func (sym_data *SymbolData) isAvailFSymbol(name string) bool {
	_, ok := sym_data.AvailSymbols[name]
	return ok
}

func (sym_data *SymbolData) initAvailSymbols() error {
	var fp *os.File
	var err error

	defer fp.Close()

	sym_data.AvailSymbols = make(map[string]bool)
	re := regexp.MustCompile(` *\[vrouter\]`)

	fp, err = os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		log.Fatalf("Failed to open available_filter_functions")
		return err
	}

	sc := bufio.NewScanner(fp)
	for sc.Scan() {
		line := sc.Text()
		fname := re.ReplaceAllString(line, "")
		sym_data.AvailSymbols[fname] = true
	}

	return nil
}

func (sym_data *SymbolData) doFillSymData(filename, name string) error {
	var fp *os.File
	var err error
	var sc *bufio.Scanner

	defer fp.Close()

	sym_data.SymList[name] = make(map[string]int64)

	fp, err = os.Open(filename)
	if err != nil {
		log.Fatalf("Failed to open %s: %s", filename, err)
		return err
	}

	sc = bufio.NewScanner(fp)
	for sc.Scan() {
		line := strings.Split(sc.Text(), " ")
		symbol := line[0]
		pos, _ := strconv.ParseInt(line[1], 10, 32)

		if !sym_data.isAvailFSymbol(symbol) {
			continue
		}

		sym_data.SymList[name][symbol] = pos
	}

	return nil
}

func (sym_data *SymbolData) FillSymData() {
	if err := sym_data.initAvailSymbols(); err != nil {
		log.Fatalf("Failed to initilalize available_filter_functions")
	}

	path := CreateVrouterBTF()
	if ret := CreateVrouterSymList(path); ret != 0 {
		log.Fatalf("Failed to write symbol list with %s", ret)
	}

	if ret := CreateVMLINUXSymList(); ret != 0 {
		log.Fatalf("Failed to write symbol list with %s", ret)
	}

	if err := sym_data.doFillSymData(vRouterSymList, "vr_packet"); err != nil {
		log.Fatalf("Failed to fill symbols of %s: %s", vRouterSymList, err)
	}

	if err := sym_data.doFillSymData(vmLinuxSymList, "sk_buff"); err != nil {
		log.Fatalf("Failed to fill symbols of %s: %s", vmLinuxSymList, err)
	}
}
