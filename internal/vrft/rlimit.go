// SPDX License identifer: BSD-3-Clause
// Copyright 2022 - 2022, Eishun Kondoh<dreamdiagnosis@gmail.com>

package vrft

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func setMemLock() error {
	var rLimit syscall.Rlimit

	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = unix.RLIM_INFINITY

	if err := syscall.Setrlimit(unix.RLIMIT_MEMLOCK, &rLimit); err != nil {
		return fmt.Errorf("Error Setting rlimit(memlock): %v", err)
	}

	return nil
}

func setStackSize() error {
	var rLimit syscall.Rlimit

	rLimit.Max = unix.RLIM_INFINITY
	rLimit.Cur = unix.RLIM_INFINITY

	if err := syscall.Setrlimit(unix.RLIMIT_STACK, &rLimit); err != nil {
		return fmt.Errorf("Error Setting rlimit(stack): %v", err)
	}

	return nil
}

func SetRlimit() error {
	if err := setMemLock(); err != nil {
		return err
	}

	if err := setStackSize(); err != nil {
		return err
	}

	return nil
}
