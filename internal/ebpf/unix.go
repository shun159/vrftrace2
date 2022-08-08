// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"bufio"
	"compress/gzip"
	"os"
	"strings"

	"github.com/spf13/viper"
)

const kernel_version = "/proc/version"
const os_version = "/etc/os-release"

type PlatformInfo struct {
	OsDist                string
	OsID                  string
	OsVersion             string
	KernelVersion         string
	IsDebugInfoBtfEnabled bool
}

func getOSRelease() (*PlatformInfo, error) {
	viper.SetConfigFile(os_version)
	viper.SetConfigType("env")
	viper.ReadInConfig()

	p := PlatformInfo{}
	p.OsDist = viper.GetString("NAME")
	p.OsID = viper.GetString("ID")
	p.OsVersion = viper.GetString("BUILD_ID")

	b, err := os.ReadFile(kernel_version)
	if err != nil {
		return nil, err
	}

	version_str := strings.Split(string(b), " ")
	kernel_version := version_str[2]
	p.KernelVersion = kernel_version

	p.checkKConfig()

	return &p, nil
}

func (pinfo *PlatformInfo) checkKConfig() error {
	fh, err := os.Open("/proc/config.gz")
	if err != nil {
		return err
	}
	defer fh.Close()

	fz, err := gzip.NewReader(fh)
	if err != nil {
		return err
	}
	defer fz.Close()

	scanner := bufio.NewScanner(fz)
	for scanner.Scan() {
		txt := scanner.Text()
		config_str_len := len(txt)
		if len(txt) > 3 && "CONFIG_DEBUG_INFO_BTF" == txt[:config_str_len-2] {
			if "y" == txt[config_str_len-1:config_str_len] {
				pinfo.IsDebugInfoBtfEnabled = true
				return nil
			}
		}
	}

	pinfo.IsDebugInfoBtfEnabled = false
	return nil
}

func GetPlatformInfo() (*PlatformInfo, error) {
	return getOSRelease()
}
