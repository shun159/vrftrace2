// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package vrft

import "embed"

//go:embed "./../dist/btfhub/*"
var BPFBundleInjected embed.FS
