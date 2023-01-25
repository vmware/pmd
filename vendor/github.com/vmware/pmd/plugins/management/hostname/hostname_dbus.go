// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package hostname

import (
	"context"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/vmware/pmd/pkg/bus"
	"github.com/vmware/pmd/pkg/parser"
)

const (
	dbusInterface = "org.freedesktop.hostname1"
	dbusPath      = "/org/freedesktop/hostname1"
)

type SDConnection struct {
	conn   *dbus.Conn
	object dbus.BusObject
}

func NewSDConnection() (*SDConnection, error) {
	conn, err := bus.SystemBusPrivateConn()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to system bus: %v", err)
	}

	return &SDConnection{
		conn:   conn,
		object: conn.Object(dbusInterface, dbus.ObjectPath(dbusPath)),
	}, nil
}

func (c *SDConnection) Close() {
	c.conn.Close()
}

func (c *SDConnection) DBusExecuteMethod(ctx context.Context, method string, value string) error {
	if err := c.object.CallWithContext(ctx, dbusInterface+"."+method, 0, value, true).Err; err != nil {
		return err
	}

	return nil
}

func (c *SDConnection) DBusDescribe(ctx context.Context) (*Describe, error) {
	desc := Describe{}

	err := c.object.CallWithContext(ctx, dbusInterface+"."+"Describe", 0).Store(&desc)
	if err != nil {
		m, err := c.DBusDescribeFallback(ctx)
		if err != nil {
			return nil, err
		}
		return m, nil
	}

	return &desc, nil
}

func (c *SDConnection) DBusDescribeFallback(ctx context.Context) (*Describe, error) {
	h := Describe{}

	var wg sync.WaitGroup
	wg.Add(17)

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".StaticHostname")
		if err == nil {
			h.StaticHostname = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".Hostname")
		if err == nil {
			h.Hostname = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".PrettyHostname")
		if err == nil {
			h.PrettyHostname = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".IconName")
		if err == nil {
			h.IconName = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".Chassis")
		if err == nil {
			h.Chassis = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".Deployment")
		if err == nil {
			h.Deployment = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".Location")
		if err == nil {
			h.Location = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".KernelName")
		if err == nil {
			h.KernelName = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".KernelRelease")
		if err == nil {
			h.KernelRelease = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".KernelVersion")
		if err == nil {
			h.KernelVersion = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".OperatingSystemPrettyName")
		if err == nil {
			h.OperatingSystemPrettyName = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".OperatingSystemCPEName")
		if err == nil {
			h.OperatingSystemCPEName = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".HomeURL")
		if err == nil {
			h.OperatingSystemHomeURL = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".HardwareVendor")
		if err == nil {
			h.HardwareVendor = s.Value().(string)
		}
	}()
	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".HardwareModel")
		if err == nil {
			h.HardwareModel = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()

		var uuid []uint8
		err := c.object.Call(dbusInterface+".GetProductUUID", 0, false).Store(&uuid)
		if err == nil {
			h.ProductUUID = parser.BuildHexFromBytes(uuid)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.object.GetProperty(dbusInterface + ".HostnameSource")
		if err == nil {
			h.HostnameSource = s.Value().(string)
		}
	}()

	wg.Wait()

	return &h, nil
}
