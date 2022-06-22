// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package login

import (
	"context"
	"fmt"

	"github.com/godbus/dbus/v5"

	"github.com/pmd-nextgen/pkg/bus"
)

const (
	dbusManagerinterface = "org.freedesktop.login1.Manager"
	dbusPath             = "/org/freedesktop/login1"
	dbusInterface        = "org.freedesktop.login1"
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

func (c *SDConnection) DBusAcquireUsersFromLogin(ctx context.Context) ([]User, error) {
	out := [][]interface{}{}
	if err := c.object.Call(dbusManagerinterface+".ListUsers", 0).Store(&out); err != nil {
		return nil, err
	}

	users := []User{}
	for _, v := range out {
		u := User{
			UID:  v[0].(uint32),
			Name: fmt.Sprintf("%v", v[1]),
			Path: fmt.Sprintf("%v", v[2]),
		}

		users = append(users, u)
	}

	return users, nil
}

func (c *SDConnection) DBusAcquireUSessionsFromLogin(ctx context.Context) ([]Session, error) {
	out := [][]interface{}{}
	if err := c.object.Call(dbusManagerinterface+".ListSessions", 0).Store(&out); err != nil {
		return nil, err
	}

	sessions := []Session{}
	for _, v := range out {
		s := Session{
			ID:   fmt.Sprintf("%v", v[0]),
			UID:  v[1].(uint32),
			User: fmt.Sprintf("%v", v[2]),
			Seat: fmt.Sprintf("%v", v[3]),
			Path: fmt.Sprintf("%v", v[4]),
		}

		sessions = append(sessions, s)
	}

	return sessions, nil
}

func (c *SDConnection) DBusAcquireUSessionFromLogin(ctx context.Context, id string) (*Session, error) {
	var out interface{}
	if err := c.object.Call(dbusManagerinterface+".GetSession", 0, id).Store(&out); err != nil {
		return nil, err
	}

	ret, ok := out.(dbus.ObjectPath)
	if !ok {
		return nil, fmt.Errorf("failed to typecast session to ObjectPath")
	}

	s := Session{
		Path: fmt.Sprintf("%v", ret),
	}
	return &s, nil
}
