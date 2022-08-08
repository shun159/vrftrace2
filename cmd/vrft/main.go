// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	ebpf "github.com/shun159/vrftrace2/internal/ebpf"
)

func signalHandler() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT)
	return sig
}

func main() {
	pinfo, err := ebpf.GetPlatformInfo()
	if err != nil {
		fmt.Printf("failed to get platform info: %s\n", err)
	}

	log.Printf("Dist Info(name = %s version = %s)\n", pinfo.OsDist, pinfo.OsVersion)
	log.Printf("Kernel(release = %s)\n", pinfo.KernelVersion)

	if pinfo.IsDebugInfoBtfEnabled {
		log.Println("DEBUG_INFO_BTF is enabled")
	} else {
		log.Println("DEBUG_INFO_BTF is disabled")
	}

	perf_map, err := ebpf.InitKprobe("/sys/kernel/btf/vmlinux")
	if err != nil {
		fmt.Printf("failed to init kprobe %+v\n", err)
	}

	perf_map.Start()

	<-signalHandler()

	perf_map.Stop()

	log.Printf("Tearing down perf buffer...\n")
}
