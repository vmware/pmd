// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package link

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func setMTU(link string, mtu int) error {
	l, err := netlink.LinkByName(link)
	if err != nil {
		log.Errorf("Failed to find link='%s': %v", link, err)
		return err
	}

	if err = netlink.LinkSetMTU(l, mtu); err != nil {
		log.Errorf("Failed to set link='%s' MTU='%d': %v", link, mtu, err)
		return err
	}

	return nil
}
