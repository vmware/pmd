// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package timedate

import (
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"

	"github.com/vmware/pmd/pkg/bus"
)

const (
	dbusInterface = "org.freedesktop.timedate1"
	dbusPath      = "/org/freedesktop/timedate1"
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

func (c *SDConnection) dBusConfigureTimeDate(property string, value string) error {
	var err error

	if property == "SetNTP" {
		err = c.object.Call(dbusInterface+"."+property, 0, true, false).Err
	} else {
		err = c.object.Call(dbusInterface+"."+property, 0, value, false).Err
	}

	return err
}

func (c *SDConnection) DBusAcquire(property string) (dbus.Variant, error) {
	p, err := c.object.GetProperty(dbusInterface + "." + property)
	if err != nil {
		return dbus.Variant{}, err
	}

	return p, nil
}

func DBusAcquireTimeDate() (*Describe, error) {
	c, err := NewSDConnection()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	h := Describe{}

	var wg sync.WaitGroup
	wg.Add(6)

	go func() {
		defer wg.Done()
		s, err := c.DBusAcquire("Timezone")
		if err == nil {
			h.Timezone = s.Value().(string)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.DBusAcquire("LocalRTC")
		if err == nil {
			h.LocalRTC = s.Value().(bool)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.DBusAcquire("CanNTP")
		if err == nil {
			h.CanNTP = s.Value().(bool)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.DBusAcquire("NTPSynchronized")
		if err == nil {
			h.NTPSynchronized = s.Value().(bool)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.DBusAcquire("TimeUSec")
		if err == nil {
			h.TimeUSec = s.Value().(uint64)
		}
	}()

	go func() {
		defer wg.Done()
		s, err := c.DBusAcquire("RTCTimeUSec")
		if err == nil {
			h.RTCTimeUSec = s.Value().(uint64)
		}
	}()

	wg.Wait()

	return &h, nil
}
