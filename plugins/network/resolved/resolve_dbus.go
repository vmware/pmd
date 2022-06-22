// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package resolved

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"syscall"

	"github.com/godbus/dbus/v5"
	"github.com/vishvananda/netlink"

	"github.com/vmware/pmd/pkg/bus"
)

const (
	dbusInterface = "org.freedesktop.resolve1"
	dbusPath      = "/org/freedesktop/resolve1"

	dbusManagerinterface = "org.freedesktop.resolve1.Manager"
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

func buildDnsMessage(variant dbus.Variant, link bool) ([]Dns, error) {
	var dns []Dns
	for _, v := range variant.Value().([][]interface{}) {
		d := Dns{}
		if link {
			d.Family = v[0].(int32)
			ip := net.IP(v[1].([]uint8))
			if d.Family == syscall.AF_INET6 {
				d.Dns = ip.To16().To16().String()
			} else {
				d.Dns = ip.To4().String()
			}
		} else {
			d.Family = v[1].(int32)
			ip := net.IP(v[2].([]uint8))
			if d.Family == syscall.AF_INET6 {
				d.Dns = ip.To16().String()
			} else {
				d.Dns = ip.To4().String()
			}

			d.Index = v[0].(int32)
			if d.Index != 0 {
				link, err := netlink.LinkByIndex(int(d.Index))
				if err != nil {
					return nil, err
				}
				d.Link = link.Attrs().Name
			}
		}
		dns = append(dns, d)
	}

	return dns, nil
}

func buildCurrentDnsMessage(variant dbus.Variant) (*Dns, error) {
	d := Dns{}
	for _, v := range variant.Value().([]interface{}) {
		if reflect.ValueOf(v).Type().Kind() == reflect.Int32 {
			d.Family = v.(int32)
		} else {
			ip := net.IP(v.([]uint8))
			if d.Family == syscall.AF_INET6 {
				d.Dns = ip.To16().To16().String()
			} else {
				d.Dns = ip.To4().String()
			}
		}
	}

	return &d, nil
}

func buildDomainsMessage(variant dbus.Variant) ([]Domains, error) {
	var domains []Domains
	for _, v := range variant.Value().([][]interface{}) {
		d := Domains{
			Domain: fmt.Sprintf("%v", v[1]),
		}

		d.Index = v[0].(int32)
		if d.Index != 0 {
			link, err := netlink.LinkByIndex(int(d.Index))
			if err != nil {
				return nil, err
			}
			d.Link = link.Attrs().Name
		}

		domains = append(domains, d)
	}
	return domains, nil
}

func (c *SDConnection) DBusAcquireDnsFromResolveLink(ctx context.Context, index int) ([]Dns, error) {
	var linkPath dbus.ObjectPath

	c.object.CallWithContext(ctx, dbusManagerinterface+".GetLink", 0, index).Store(&linkPath)
	variant, err := c.conn.Object("org.freedesktop.resolve1", linkPath).GetProperty("org.freedesktop.resolve1.Link.DNS")
	if err != nil {
		return nil, fmt.Errorf("error fetching DNS from resolved: %v", err)
	}

	return buildDnsMessage(variant, true)
}

func (c *SDConnection) DBusAcquireCurrentDnsFromResolveLink(ctx context.Context, index int) (*Dns, error) {
	var linkPath dbus.ObjectPath

	c.object.CallWithContext(ctx, dbusManagerinterface+".GetLink", 0, index).Store(&linkPath)
	variant, err := c.conn.Object("org.freedesktop.resolve1", linkPath).GetProperty("org.freedesktop.resolve1.Link.CurrentDNSServer")
	if err != nil {
		return nil, fmt.Errorf("error fetching DNS from resolved: %v", err)
	}

	return buildCurrentDnsMessage(variant)
}

func (c *SDConnection) DBusAcquireDomainsFromResolveLink(ctx context.Context, index int) ([]Domains, error) {
	var linkPath dbus.ObjectPath

	c.object.CallWithContext(ctx, dbusManagerinterface+".GetLink", 0, index).Store(&linkPath)
	variant, err := c.conn.Object("org.freedesktop.resolve1", linkPath).GetProperty("org.freedesktop.resolve1.Link.Domains")
	if err != nil {
		return nil, fmt.Errorf("error fetching Domains from resolved: %v", err)
	}

	return buildDomainsMessage(variant)
}

func (c *SDConnection) DBusAcquireDnsFromResolveManager(ctx context.Context) ([]Dns, error) {
	variant, err := c.object.GetProperty(dbusManagerinterface + ".DNS")
	if err != nil {
		return nil, fmt.Errorf("error fetching DNS from resolved: %v", err)
	}

	return buildDnsMessage(variant, false)
}

func (c *SDConnection) DBusAcquireCurrentDnsFromResolveManager(ctx context.Context) ([]Dns, error) {
	variant, err := c.object.GetProperty(dbusManagerinterface + ".CurrentDNSServer")
	if err != nil {
		return nil, fmt.Errorf("error fetching current DNS from resolved: %v", err)
	}

	return buildDnsMessage(variant, false)
}

func (c *SDConnection) DBusAcquireDomainsFromResolveManager(ctx context.Context) ([]Domains, error) {
	variant, err := c.object.GetProperty(dbusManagerinterface + ".Domains")
	if err != nil {
		return nil, fmt.Errorf("error fetching Domains from resolved: %v", err)
	}

	return buildDomainsMessage(variant)
}
