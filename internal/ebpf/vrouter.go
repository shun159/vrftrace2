// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/shun159/vr"

	vr_raw "github.com/shun159/vr/vr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const NL_ATTR_VR_MESSAGE_PROTOCOL = 1
const SANDESH_REQUEST = 1

//
// Sandesh protocol and transport
//
type Sandesh struct {
	context   context.Context
	transport *thrift.TMemoryBuffer
	protocol  *vr.TSandeshProtocol
}

//
// vrouter interface
//
type VrouterIface struct {
	Type  int32
	Idx   int32
	OsIdx int32
	Name  string
}

//
// check if vrouter.ko is loaded on the system from /proc/module.
// See: How to find information about the kernel modules installed on the system
// https://access.redhat.com/solutions/4246821
//
func IsVrouterKmodLoaded() bool {
	const KMOD_CHECK_CMD = "cat /proc/modules | grep -c vrouter"

	res, err := exec.Command("sh", "-c", KMOD_CHECK_CMD).CombinedOutput()
	cmd := strings.Replace(string(res), "\n", "", -1)

	if err != nil || cmd != "1" {
		return false
	}

	return true
}

//
// Build and send a netlink message request with an sandesh
// nlattr to vrouter kernel module. This function blocks until response received
// See: https://github.com/tungstenfabric/tf-vrouter/blob/master/linux/vr_genetlink.c
//
// this function returns response binaries from vrouter.
//
func execNlMsg(data []byte) ([][]byte, error) {
	family, err := netlink.GenlFamilyGet("vrouter")
	if err != nil {
		return [][]byte{}, err
	}

	msg := &nl.Genlmsg{
		Command: NL_ATTR_VR_MESSAGE_PROTOCOL,
		Version: 0,
	}

	req := nl.NewNetlinkRequest(int(family.ID), 0)
	req.AddData(msg)
	req.AddData(nl.NewRtAttr(SANDESH_REQUEST, data))
	msgs, err := req.Execute(unix.NETLINK_GENERIC, 0)

	return msgs, err
}

//
// Instantiate Sandesh protocol
//
func newSandesh() *Sandesh {
	mem_buffer := thrift.NewTMemoryBuffer()
	vrouter := vr.NewTSandeshProtocolTransport(mem_buffer)
	sandesh := &Sandesh{
		context:   context.Background(),
		transport: mem_buffer,
		protocol:  vrouter,
	}

	return sandesh
}

//
// send/receive a sandesh message over netlink protocol.
// If the request succeed vrouter will send a list of sandesh message with
// vr_response message in 0th and response message in 1st element.
//
// this function returns a response binary
// if resp_code of vr_response is 0, otherwise error will not be nil.
//
func (sandesh *Sandesh) sendRequest(data []byte) ([]byte, error) {
	msg_bytes, err := execNlMsg(data)

	if err != nil {
		return nil, err
	} else if len(msg_bytes) < 2 {
		return nil, errors.New("netlink message too short (length < 2)")
	}

	vr_resp_buf := bytes.NewBuffer(msg_bytes[0])
	vr_resp := vr_raw.NewVrResponse()
	sandesh.transport.Buffer = vr_resp_buf

	vr_resp.Read(sandesh.context, sandesh.protocol)

	if vr_resp.RespCode != 0 {
		return nil, errors.New("vr_response.resp_code != 0")
	}

	return msg_bytes[1], nil
}

//
// decode a binary into an array of vifr objects
//
func (sandesh *Sandesh) decodeDumpVrInterfaceReq(data []byte) ([]vr_raw.VrInterfaceReq, error) {
	var interfaces []vr_raw.VrInterfaceReq
	var req vr_raw.VrInterfaceReq

	sandesh.transport.Buffer = bytes.NewBuffer(data[8:])

	for {
		if sandesh.transport.Buffer.Len() < 8 {
			return interfaces, nil
		}

		req = *vr_raw.NewVrInterfaceReq()
		if err := req.Read(sandesh.context, sandesh.protocol); err != nil {
			return []vr_raw.VrInterfaceReq{}, err
		}

		interfaces = append(interfaces, req)
	}
}

//
// send vr_interface_req with dump_op to vrouter kernel
//
func (sandesh *Sandesh) SendVifDumpRequest() ([]byte, error) {
	req := &vr_raw.VrInterfaceReq{}
	req.HOp = vr.SANDESH_OPER_DUMP
	req.VifrMarker = -1
	req.VifrRid = 0
	req.VifrCore = 0

	if err := req.Write(sandesh.context, sandesh.protocol); err != nil {
		return nil, errors.New("failed to encode request into binary")
	}

	req_b := sandesh.transport.Bytes()
	rep_b, err := sandesh.sendRequest(req_b)

	if err != nil {
		return nil, fmt.Errorf("failed to send vr_interface_req: %v", err)
	}

	return rep_b, nil
}

func DumpVrInterfaces() (*[]VrouterIface, error) {
	var err error

	if !IsVrouterKmodLoaded() {
		return nil, errors.New("vrouter.ko is not loaded")
	}

	sandesh := newSandesh()

	b, err := sandesh.SendVifDumpRequest()
	if err != nil {
		return nil, fmt.Errorf("failed to build vr_interface_req: %v", err)
	}

	vifs, err := sandesh.decodeDumpVrInterfaceReq(b)
	if err != nil {
		return nil, fmt.Errorf("failed to decode dump vr_interface response: %v", err)
	}

	ifaces := []VrouterIface{}

	for _, vif := range vifs {
		ifaces = append(ifaces, VrouterIface{
			Type:  vif.VifrType,
			Idx:   vif.VifrIdx,
			OsIdx: vif.VifrOsIdx,
			Name:  vif.VifrName,
		})
	}

	return &ifaces, err
}
