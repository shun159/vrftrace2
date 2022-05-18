// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package vrft

import (
	flags "github.com/jessevdk/go-flags"
	"log"
)

type Options struct {
	Vmlinux string `short:"l" long:"vmlinux" default:"/sys/kernel/btf/vmlinux" description:"Kernel vmlinux BTF file"`
	Vrouter string `short:"r" long:"vrouter" default:"builtin" description:"vrouter BTF file"`
}

var opts Options

func ParseOptions() Options {
	parser := flags.NewParser(&opts, flags.Default)
	parser.Usage = "[opts]"
	_, err := parser.Parse()
	if err != nil {
		log.Fatalf("Failed to parse command line argument")
	}

	return opts
}
