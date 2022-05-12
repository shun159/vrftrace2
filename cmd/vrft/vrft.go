// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package main

import (
	"log"
	"os"
	"os/signal"
	"os/user"
	"syscall"

	"internal/vrft"
)

func sigHandler() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT)
	return sig
}

func main() {
    vrft.GetKernelinfo("/tmp/vrft.btf")

	user, err := user.Current()
	if err != nil {
		log.Fatalf("Failed to get current user")
	}

	if user.Uid != "0" {
		log.Fatalf("must be root to use eBPF")
	}

	if err := vrft.SetRlimit(); err != nil {
		log.Fatalf("Failed: %v", err)
	}

	sym_data, err := vrft.InitSymbolData()
	if err != nil {
		log.Fatalf("Failed to instantiate a symbol_database")
	}

	sym_data.FillSymData()

	perfmap, err := vrft.InitBPF(sym_data)
	if err != nil {
		log.Fatalf("Failed to initialize BPF progs or maps: %+v", err)
	}

	perfmap.Start()

	<-sigHandler()

    vrft.TeardownSymbolData()

	perfmap.Stop()
}
