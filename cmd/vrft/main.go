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

	embed "github.com/shun159/vrftrace2"
	ebpf "github.com/shun159/vrftrace2/internal/ebpf"
	"github.com/urfave/cli"
)

const VERSION = "0.0.1"
const DEFAULT_LINUX_BTF = "/sys/kernel/btf/vmlinux"

func main() {
	app := newApp(VERSION)
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("%+v", err)
	}

	os.Exit(0)
}

func signalHandler() chan os.Signal {
	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT)
	return sig
}

func symdbArgs(vmlinux_btf, vrouter_btf string) ebpf.SymbolDbArgs {
	args := ebpf.SymbolDbArgs{
		Btf: map[string][]string{
			"vr_packet": {
				vrouter_btf,
			},
			"sk_buff": {
				vmlinux_btf,
				vrouter_btf,
			},
		},
	}

	return args
}

func deployArtifacts() error {
	if err := embed.DeployKprobeMod(); err != nil {
		return err
	}

	if err := embed.DeployVrouterBTF(); err != nil {
		return err
	}

	return nil
}

func newApp(version string) *cli.App {
	app := cli.NewApp()

	app.Name = "vrftrace"
	app.Version = version
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "kernel-btf",
			Usage: "Linux kernel BTF file",
			Value: "/sys/kernel/btf/vmlinux",
		},
		cli.StringFlag{
			Name:  "vrouter-btf",
			Usage: "tf-vrouter.ko BTF file",
			Value: "/tmp/vrouter.btf",
		},
	}

	app.Action = run
	return app
}

func run(ctx *cli.Context) error {
	vmlinux := ctx.String("kernel-btf")
	vrouter := ctx.String("vrouter-btf")
	symargs := symdbArgs(vmlinux, vrouter)

	pinfo, err := ebpf.GetPlatformInfo()
	if err != nil {
		return fmt.Errorf("failed to get platform info: %s\n", err)
	}

	log.Printf("Dist Info(name = %s version = %s)\n", pinfo.OsDist, pinfo.OsVersion)
	log.Printf("Kernel(release = %s)\n", pinfo.KernelVersion)

	if pinfo.IsDebugInfoBtfEnabled {
		log.Println("DEBUG_INFO_BTF is enabled")
	} else {
		log.Println("DEBUG_INFO_BTF is disabled")
		if vmlinux == DEFAULT_LINUX_BTF {
			log.Fatalf("kernel-btf option must be specified")
		}
	}

	log.Printf("Linux Debug info: %s\n", vmlinux)

	if err := deployArtifacts(); err != nil {
		log.Fatalf("failed to deploy artifacts: %s\n", err)
	}

	log.Printf("tf-vrouter Debug info: %s\n", vrouter)

	perf_map, err := ebpf.InitKprobe(vmlinux, symargs)

	if err != nil {
		return fmt.Errorf("failed to init kprobe %+v\n", err)
	}

	perf_map.Start()

	<-signalHandler()

	perf_map.Stop()

	log.Printf("Tearing down perf buffer...\n")

	return nil
}
