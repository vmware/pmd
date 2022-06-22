// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package timesyncd

import (
	"context"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/bus"
	"github.com/vmware/pmd/pkg/parser"
)

const (
	dbusInterface = "org.freedesktop.timesync1"
	dbusPath      = "/org/freedesktop/timesync1"

	dbusManagerinterface = "org.freedesktop.timesync1.Manager"
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

func (c *SDConnection) DBusAcquireCurrentNTPServerFromTimeSync(ctx context.Context) (string, int32, string, error) {
	var wg sync.WaitGroup
	var err error
	wg.Add(2)

	var serverName dbus.Variant
	go func() {
		defer wg.Done()
		serverName, err = c.object.GetProperty(dbusManagerinterface + ".ServerName")
		if err != nil {
			log.Errorf("Failed to acquire 'ServerName': %v", err)
		}
	}()

	var serverAddress dbus.Variant
	go func() {
		defer wg.Done()
		serverAddress, err = c.object.GetProperty(dbusManagerinterface + ".ServerAddress")
		if err != nil {
			log.Errorf("Failed to acquire 'ServerAddress': %v", err)
		}
	}()

	wg.Wait()

	if err != nil {
		return "", 0, "", err
	}

	return serverName.Value().(string),
		serverAddress.Value().([]interface{})[0].(int32),
		parser.BuildIPFromBytes(serverAddress.Value().([]interface{})[1].([]uint8)),
		nil
}

func (c *SDConnection) DBusAcquireSystemNTPServersFromTimeSync(ctx context.Context) ([]string, error) {
	s, err := c.object.GetProperty(dbusManagerinterface + ".SystemNTPServers")
	if err != nil {
		return nil, err
	}

	return s.Value().([]string), nil
}

func (c *SDConnection) DBusAcquireLinkNTPServersFromTimeSync(ctx context.Context) ([]string, error) {
	s, err := c.object.GetProperty(dbusManagerinterface + ".LinkNTPServers")
	if err != nil {
		return nil, err
	}

	return s.Value().([]string), nil
}
