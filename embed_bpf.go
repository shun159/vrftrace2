// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package vrft

import (
	"embed"
	"log"
	"os"
)

//go:embed "dist/vmlinux"
//go:embed "dist/vrouter.btf"
//go:embed "dist/vrftrace_kprobe.bpf.o"
var BPFBundleInjected embed.FS

func deployEmbedFile(src, dst string) error {
	b, err := BPFBundleInjected.ReadFile(src)
	if err != nil {
		log.Printf("Failed to read %s %s", src, err)
		return err
	}

	fh, err := os.Create(dst)
	if err != nil {
		log.Printf("Failed to create  %s %s", dst, err)
		return err
	}

	defer fh.Close()

	_, err = fh.Write(b)
	if err != nil {
		log.Printf("Failed to write %s %s", dst, err)
		return err
	}

	return nil

}

func DeployVrouterBTF() error {
	return deployEmbedFile("dist/vrouter.btf", "/tmp/vrouter.btf")
}

func DeployKprobeMod() error {
	return deployEmbedFile("dist/vrftrace_kprobe.bpf.o", "/tmp/vrftrace_kprobe.bpf.o")
}

func DeployVmlinux() error {
	return deployEmbedFile("dist/vmlinux", "/tmp/vmlinux")
}
