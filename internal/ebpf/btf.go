// Copyright 2022 shun159 <dreamdiagnosis@gmail.com>. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ebpf

/*
#include <stdlib.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

int __btf_type_type(const struct btf_type *t)
{
    return t->type;
}

int __btf_param_type(const struct btf_param *p)
{
    return p->type;
}
*/
import "C"

import (
	"syscall"
	"unsafe"
)

type BTF struct {
	Btf *C.struct_btf
}

type BTFType struct {
	NameOff uint32
	/* "info" bits arrangement
	 * bits  0-15: vlen (e.g. # of struct's members)
	 * bits 16-23: unused
	 * bits 24-27: kind (e.g. int, ptr, array...etc)
	 * bits 28-30: unused
	 * bit     31: kind_flag, currently used by
	 *             struct, union and fwd
	 */
	Info uint32
	/* "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
	* FUNC, FUNC_PROTO, VAR, DECL_TAG and TYPE_TAG.
	* "type" is a type_id referring to another type.
	 */
	Type uint32

	// kind of this BTF type
	Kind string
	// Name of this BTF type
	Name string

	// raw pointer of btf_type
	t *C.struct_btf_type
}

type BtfFuncProto struct {
	/*
	 * name of the function
	 */
	Name string

	/*
	 * Arguments of the function
	 */
	Vargs []string
}

type BTFKind uint16

const (
	BTF_KIND_UNKN       BTFKind = iota /* Unknown	*/
	BTF_KIND_INT                       /* Integer	*/
	BTF_KIND_PTR                       /* Pointer	*/
	BTF_KIND_ARRAY                     /* Array	*/
	BTF_KIND_STRUCT                    /* Struct	*/
	BTF_KIND_UNION                     /* Union	*/
	BTF_KIND_ENUM                      /* Enumeration	*/
	BTF_KIND_FWD                       /* Forward	*/
	BTF_KIND_TYPEDEF                   /* Typedef	*/
	BTF_KIND_VOLATILE                  /* Volatile	*/
	BTF_KIND_CONST                     /* Const	*/
	BTF_KIND_RESTRICT                  /* Restrict	*/
	BTF_KIND_FUNC                      /* Function	*/
	BTF_KIND_FUNC_PROTO                /* Function Proto	*/
	BTF_KIND_VAR                       /* Variable	*/
	BTF_KIND_DATASEC                   /* Section	*/
	BTF_KIND_FLOAT                     /* Floating point	*/
	BTF_KIND_DECL_TAG                  /* Decl Tag */
	BTF_KIND_TYPE_TAG                  /* Type Tag */

	NR_BTF_KINDS
	BTF_KIND_MAX = NR_BTF_KINDS - 1
)

func (kind BTFKind) String() string {
	switch kind {
	case BTF_KIND_UNKN:
		return "UNKNOWN"
	case BTF_KIND_INT:
		return "INT"
	case BTF_KIND_PTR:
		return "PTR"
	case BTF_KIND_ARRAY:
		return "ARRAY"
	case BTF_KIND_STRUCT:
		return "STRUCT"
	case BTF_KIND_UNION:
		return "UNION"
	case BTF_KIND_ENUM:
		return "ENUM"
	case BTF_KIND_FWD:
		return "FWD"
	case BTF_KIND_TYPEDEF:
		return "TYPEDEF"
	case BTF_KIND_VOLATILE:
		return "VOLATILE"
	case BTF_KIND_CONST:
		return "CONST"
	case BTF_KIND_RESTRICT:
		return "RESTRICT"
	case BTF_KIND_FUNC:
		return "FUNC"
	case BTF_KIND_FUNC_PROTO:
		return "FUNC_PROTO"
	case BTF_KIND_VAR:
		return "VAR"
	case BTF_KIND_DATASEC:
		return "DATASEC"
	case BTF_KIND_FLOAT:
		return "FLOAT"
	case BTF_KIND_DECL_TAG:
		return "DECL_TAG"
	case BTF_KIND_TYPE_TAG:
		return "TYPE_TAG"
	}
	return "UNKNOWN"
}

func (t *BTFType) IsVoid() bool {
	return t.Kind == "UNKNOWN"
}

func (t *BTFType) IsInt() bool {
	return t.Kind == "INT"
}

func (t *BTFType) IsPtr() bool {
	return t.Kind == "PTR"
}

func (t *BTFType) IsArray() bool {
	return t.Kind == "ARRAY"
}

func (t *BTFType) IsStruct() bool {
	return t.Kind == "STRUCT"
}

func (t *BTFType) IsUnion() bool {
	return t.Kind == "UNION"
}

func (t *BTFType) IsComposite() bool {
	return t.IsUnion() || t.IsStruct()
}

func (t *BTFType) IsEnum() bool {
	return t.Kind == "ENUM"
}

func (t *BTFType) IsFwd() bool {
	return t.Kind == "FWD"
}

func (t *BTFType) IsTypedef() bool {
	return t.Kind == "TYPEDEF"
}

func (t *BTFType) IsVolatile() bool {
	return t.Kind == "VOLATILE"
}

func (t *BTFType) IsConst() bool {
	return t.Kind == "CONST"
}

func (t *BTFType) IsRestrict() bool {
	return t.Kind == "RESTRICT"
}

func (t *BTFType) IsMod() bool {
	return t.IsVolatile() ||
		t.IsConst() ||
		t.IsRestrict() ||
		t.IsTypeTag()
}

func (t *BTFType) IsFunc() bool {
	return t.Kind == "FUNC"
}

func (t *BTFType) IsFuncProto() bool {
	return t.Kind == "FUNC_PROTO"
}

func (t *BTFType) IsVar() bool {
	return t.Kind == "VAR"
}

func (t *BTFType) IsDataSec() bool {
	return t.Kind == "DATASEC"
}

func (t *BTFType) IsFloat() bool {
	return t.Kind == "FLOAT"
}

func (t *BTFType) IsDeclTag() bool {
	return t.Kind == "DECL_TAG"
}

func (t *BTFType) IsTypeTag() bool {
	return t.Kind == "TYPE_TAG"
}

/*
 * libbpf pointer into a stderr code (or 0 if the pointer is valid)
 */
func GetBpfError(p *C.struct_btf) error {
	errno := C.libbpf_get_error(unsafe.Pointer(p))

	if errno != 0 {
		return syscall.Errno(-errno)
	}

	return nil
}

/*
 * Probe few well-known locations for vmlinux kernel image and try to load BTF
 * data out of it to use for target BTF.
 */
func LoadVmlinuxBtf() (*BTF, error) {
	btf := C.btf__load_vmlinux_btf()

	if err := GetBpfError(btf); err != nil {
		return nil, err
	}

	return &BTF{Btf: btf}, nil
}

/*
 * libbpf API to parse BTF data from file.
 */
func ParseRaw(path string) (*BTF, error) {
	c_path := C.CString(path)
	defer C.free(unsafe.Pointer(c_path))

	btf := C.btf__parse_raw(c_path)
	if err := GetBpfError(btf); err != nil {
		return nil, err
	}

	return &BTF{Btf: btf}, nil
}

/*
 * used to load module BTF, overrides with loaded BTF
 */
func (vmlinux_btf *BTF) LoadModuleBTF(module string) error {
	c_module := C.CString(module)
	defer C.free(unsafe.Pointer(c_module))

	btf := C.btf__load_module_btf(c_module, vmlinux_btf.Btf)
	if err := GetBpfError(btf); err != nil {
		return err
	}

	vmlinux_btf.Btf = btf

	return nil
}

/*
 * Get btf_type by id
 */
func (vmlinux_btf *BTF) BtfTypeById(id int) *BTFType {
	c_btf_type := C.btf__type_by_id(vmlinux_btf.Btf, C.uint(id))

	if c_btf_type == nil {
		return nil
	}

	kind := BTFKind(C.btf_kind(c_btf_type))

	btf_type := &BTFType{}
	btf_type.t = c_btf_type
	btf_type.NameOff = uint32(c_btf_type.name_off)
	btf_type.Info = uint32(c_btf_type.info)
	btf_type.Kind = BTFKind.String(kind)
	btf_type.Type = uint32(C.__btf_type_type(c_btf_type))

	c_name := C.btf__str_by_offset(vmlinux_btf.Btf, C.uint(btf_type.NameOff))
	btf_type.Name = C.GoString(c_name)

	return btf_type
}

/*
 * Resolve function proto from the BTF
 */
func (vmlinux_btf *BTF) BtfFuncProto(btf_type *BTFType, id int) BtfFuncProto {
	func_t := vmlinux_btf.BtfTypeById(int(btf_type.Type))

	c_params := C.btf_params(func_t.t)
	params := *(*[]C.struct_btf_param)(unsafe.Pointer(&c_params))

	vlen := int(C.btf_vlen(func_t.t))
	vargs := []string{}

	for i := 0; i < vlen; i++ {
		param_type := C.__btf_param_type(&params[i])
		varg_t := vmlinux_btf.BtfTypeById(int(param_type))
		if varg_t.IsPtr() {
			varg_t = vmlinux_btf.BtfTypeById(int(varg_t.Type))
		}
		vargs = append(vargs, varg_t.Name)
	}

	func_proto := BtfFuncProto{}
	func_proto.Name = btf_type.Name
	func_proto.Vargs = vargs

	return func_proto
}
