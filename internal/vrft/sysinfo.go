package vrft

import (
	"log"
	"os"

	//embed "github.com/shun159/vrftrace2"
	"github.com/zcalusic/sysinfo"
)

var (
	VMLINUX       = "/sys/kernel/btf/vmlinux"
	baseBTFDir    = "dist/btfhub/%s/%s/%s/%s.btf"
	defaultBTFDir = "/tmp/vmlinux"
)

type KernelInfo struct {
	Hostname      string
	OSVendor      string
	OSRelease     string
	KernelRelease string
	KernelArch    string
	BTFfilename   string
}

func GetKernelinfo(btfFilePath string) (*KernelInfo, error) {
	var si sysinfo.SysInfo
	kinfo := KernelInfo{}

	si.GetSysInfo()
	nodeinfo := si.Node
	osinfo := si.OS
	kernelinfo := si.Kernel

	kinfo.Hostname = nodeinfo.Hostname
	kinfo.OSVendor = osinfo.Vendor
	kinfo.OSRelease = osinfo.Release
	kinfo.KernelRelease = kernelinfo.Release
	kinfo.KernelArch = kernelinfo.Architecture

	if err := kinfo.PickBTFFile(btfFilePath); err != nil {
		return nil, err
	}

	return &kinfo, nil
}

func (kinfo *KernelInfo) PickBTFFile(bpfFilePath string) error {
	kinfo.BTFfilename = bpfFilePath

	if bpfFilePath == VMLINUX {
		log.Printf("Load %s BTF file\n", VMLINUX)
		return nil
	}

	if _, err := os.Stat(bpfFilePath); err != nil {
		log.Printf("Couldn't found %s, load %s instead\n", bpfFilePath, defaultBTFDir)
		kinfo.BTFfilename = defaultBTFDir
		return nil
	}

	return nil
}
