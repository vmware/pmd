// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package system

import (
	"syscall"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
)

func ApplyCapability(cred *syscall.Credential) error {
	caps, err := capability.NewPid2(0)
	if err != nil {
		return err
	}

	allCapabilityTypes := capability.CAPS | capability.BOUNDS | capability.AMBS

	caps.Clear(capability.CAPS | capability.BOUNDS | capability.AMBS)
	caps.Set(capability.BOUNDS, capability.CAP_NET_ADMIN, capability.CAP_SYS_ADMIN, capability.CAP_NET_BIND_SERVICE)
	caps.Set(capability.PERMITTED, capability.CAP_NET_ADMIN, capability.CAP_SYS_ADMIN, capability.CAP_NET_BIND_SERVICE)
	caps.Set(capability.INHERITABLE, capability.CAP_NET_ADMIN, capability.CAP_SYS_ADMIN, capability.CAP_NET_BIND_SERVICE)
	caps.Set(capability.EFFECTIVE, capability.CAP_NET_ADMIN, capability.CAP_SYS_ADMIN, capability.CAP_NET_BIND_SERVICE)

	caps.Clear(capability.AMBIENT)
	return caps.Apply(allCapabilityTypes)
}

func EnableKeepCapability() error {
	return unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0)
}

func DisableKeepCapability() error {
	return unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0)
}
