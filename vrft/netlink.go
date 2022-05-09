// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package vrft

import (
	"bytes"
	"context"
	"errors"
	"log"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/shun159/vr"

	vr_raw "github.com/shun159/vr/vr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const NL_ATTR_VR_MESSAGE_PROTOCOL = 1
const SANDESH_REQUEST = 1

func sendNlMsg(data []byte) ([][]byte, error) {
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

func sendSandeshRequest(data []byte) ([]byte, error) {
	ctx := context.Background()
	transport := thrift.NewTMemoryBuffer()
	protocol := vr.NewTSandeshProtocolTransport(transport)

	msg_bytes, err := sendNlMsg(data)
	if err != nil {
		return nil, err
	} else if len(msg_bytes) < 2 {
		return nil, errors.New("netlink message too short (length < 2)")
	}

	vr_resp_buf := bytes.NewBuffer(msg_bytes[0])
	vr_resp := vr_raw.NewVrResponse()
	transport.Buffer = vr_resp_buf
	vr_resp.Read(ctx, protocol)

	if vr_resp.RespCode != 0 {
		return nil, errors.New("vr_response.resp_code != 0")
	}

	return msg_bytes[1], nil
}

func newVifDumpRequest() *vr_raw.VrInterfaceReq {
	req := &vr_raw.VrInterfaceReq{}
	req.HOp = vr.SANDESH_OPER_DUMP
	req.VifrMarker = -1
	req.VifrRid = 0
	req.VifrCore = 0

	return req
}

func decodeDumpVrInterfaceReq(data []byte) ([]vr_raw.VrInterfaceReq, error) {
	var interfaces []vr_raw.VrInterfaceReq
	var req vr_raw.VrInterfaceReq

	ctx := context.Background()
	transport := thrift.NewTMemoryBuffer()
	protocol := vr.NewTSandeshProtocolTransport(transport)
	transport.Buffer = bytes.NewBuffer(data[8:])

	for {
		if transport.Buffer.Len() < 8 {
			return interfaces, nil
		}

		req = *vr_raw.NewVrInterfaceReq()
		if err := req.Read(ctx, protocol); err != nil {
			return []vr_raw.VrInterfaceReq{}, err
		}

		interfaces = append(interfaces, req)
	}
}

func DumpInterfaces() ([]vr_raw.VrInterfaceReq, error) {
	ctx := context.Background()
	transport := thrift.NewTMemoryBuffer()
	protocol := vr.NewTSandeshProtocolTransport(transport)

	req := newVifDumpRequest()
	if err := req.Write(ctx, protocol); err != nil {
		log.Fatalf("Failed to encode request into binary")
	}

	req_b := transport.Bytes()
	msg_bytes, err := sendSandeshRequest(req_b)

	if err != nil {
		log.Fatalf("Failed to send vr_interface_req: %v", err)
	}

	vifs, err := decodeDumpVrInterfaceReq(msg_bytes)
	if err != nil {
		log.Fatalf("Failed to decode dump vr_interface response: %v", err)
	}

	return vifs, err
}
