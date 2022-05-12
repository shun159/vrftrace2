package vrft

import (
	"fmt"
	"io"
	"os"

	embed "github.com/shun159/vrftrace2"
	"github.com/zcalusic/sysinfo"
)

var (
	VMLINUX    = "/sys/kernel/btf/vmlinux"
	baseBTFDir = "dist/btfhub/%s/%s/%s/%s.btf"
)

type KernelInfo struct {
	Hostname      string
	OSVendor      string
	OSRelease     string
	KernelRelease string
	KernelArch    string
	BTFfilename   string
}

func GetKernelinfo(btfOutFilePath string) (*KernelInfo, error) {
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

	if err := kinfo.PickBTFFile(btfOutFilePath); err != nil {
		return nil, err
	}

	return &kinfo, nil
}

func (kinfo *KernelInfo) PickBTFFile(outFilePath string) error {
	var btfFileName string

	btfFileName = fmt.Sprintf(
		baseBTFDir,
		kinfo.OSVendor,
		kinfo.OSRelease,
		kinfo.KernelArch,
		kinfo.KernelRelease,
	)

	if _, err := os.Stat(VMLINUX); err == nil {
		kinfo.BTFfilename = VMLINUX
        return nil
	}

	btfFile, err := embed.BPFBundleInjected.Open(btfFileName)
	if err != nil {
		return fmt.Errorf("error opening embedded btfhub file: %s", err.Error())
	}
	defer btfFile.Close()

	outFile, err := os.Create(outFilePath)
	if err != nil {
		return fmt.Errorf("could not create btf file: %s", err.Error())
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, btfFile); err != nil {
		return fmt.Errorf("error copying embedded btfhub file: %s", err.Error())
	}

	kinfo.BTFfilename = outFilePath

	return nil
}
