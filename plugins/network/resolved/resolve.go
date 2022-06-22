// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package resolved

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/pmd-nextgen/pkg/configfile"
	"github.com/pmd-nextgen/pkg/share"
	"github.com/pmd-nextgen/pkg/validator"
	"github.com/pmd-nextgen/pkg/web"
	"github.com/pmd-nextgen/plugins/systemd"
)

type Dns struct {
	Index  int32  `json:"Index"`
	Link   string `json:"Link"`
	Family int32  `json:"Family"`
	Dns    string `json:"Dns"`
}

type Domains struct {
	Index  int32  `json:"Index"`
	Link   string `json:"Link"`
	Domain string `json:"Domain"`
}

type Describe struct {
	CurrentDNS     string    `json:"CurrentDns"`
	DnsServers     []Dns     `json:"DnsServers"`
	LinkCurrentDNS []Dns     `json:"LinkCurrentDns"`
	Domains        []Domains `json:"Domains"`
}

type GlobalDns struct {
	DnsServers []string `json:"DnsServers"`
	Domains    []string `json:"Domains"`
}

func decodeJSONRequest(r *http.Request) (*GlobalDns, error) {
	dns := GlobalDns{}
	if err := json.NewDecoder(r.Body).Decode(&dns); err != nil {
		return nil, err
	}

	return &dns, nil
}

func AcquireLinkDns(ctx context.Context, link string, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	l, err := netlink.LinkByName(link)
	if err != nil {
		return err
	}

	links, err := c.DBusAcquireDnsFromResolveLink(ctx, l.Attrs().Index)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	return web.JSONResponse(links, w)
}

func AcquireLinkCurrentDns(ctx context.Context, link string, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	l, err := netlink.LinkByName(link)
	if err != nil {
		return err
	}

	dns, err := c.DBusAcquireCurrentDnsFromResolveLink(ctx, l.Attrs().Index)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	dns.Link = l.Attrs().Name
	dns.Index = int32(l.Attrs().Index)

	return web.JSONResponse(dns, w)
}

func AcquireLinkDomains(ctx context.Context, link string, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	l, err := netlink.LinkByName(link)
	if err != nil {
		return err
	}

	d, err := c.DBusAcquireDomainsFromResolveLink(ctx, l.Attrs().Index)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	return web.JSONResponse(d, w)
}

func AcquireDns(ctx context.Context) ([]Dns, error) {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return nil, err
	}
	defer c.Close()

	dns, err := c.DBusAcquireDnsFromResolveManager(ctx)
	if err != nil {
		return nil, err
	}

	return dns, nil
}

func AcquireDomains(ctx context.Context) ([]Domains, error) {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return nil, err
	}
	defer c.Close()

	domains, err := c.DBusAcquireDomainsFromResolveManager(ctx)
	if err != nil {
		return nil, err
	}

	return domains, nil
}

func DescribeDns(ctx context.Context) (*Describe, error) {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return nil, err
	}
	defer c.Close()

	d := Describe{}
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		dns, err := c.DBusAcquireDnsFromResolveManager(ctx)
		if err == nil {
			d.DnsServers = dns
		}
	}()

	go func() {
		defer wg.Done()
		domains, err := c.DBusAcquireDomainsFromResolveManager(ctx)
		if err == nil {
			d.Domains = domains
		}
	}()

	go func() {
		defer wg.Done()

		links, _ := netlink.LinkList()
		for _, l := range links {
			if l.Attrs().Index == 1 {
				continue
			}

			dns, err := c.DBusAcquireCurrentDnsFromResolveLink(ctx, l.Attrs().Index)
			if err == nil {
				dns.Link = l.Attrs().Name
				dns.Index = int32(l.Attrs().Index)
				d.LinkCurrentDNS = append(d.LinkCurrentDNS, *dns)
			}
		}
	}()

	wg.Wait()
	return &d, nil
}

func restartResolved(ctx context.Context) error {
	u := systemd.UnitAction{
		Unit:   "systemd-resolved.service",
		Action: "restart",
	}

	if err := u.UnitCommands(ctx); err != nil {
		return err
	}

	return nil
}

func (d *GlobalDns) AddDns(ctx context.Context, w http.ResponseWriter) error {
	m, err := configfile.Load("/etc/systemd/resolved.conf")
	if err != nil {
		return err
	}

	if !validator.IsArrayEmpty(d.DnsServers) {
		if !validator.IsIPs(d.DnsServers) {
			return errors.New("invalid Ips")
		}

		s := m.GetKeySectionString("Resolve", "DNS")
		t := share.UniqueSlices(strings.Split(s, " "), d.DnsServers)
		m.SetKeySectionString("Resolve", "DNS", strings.Join(t[:], " "))
	}
	if !validator.IsArrayEmpty(d.Domains) {
		s := m.GetKeySectionString("Resolve", "Domains")
		t := share.UniqueSlices(strings.Split(s, " "), d.Domains)
		m.SetKeySectionString("Resolve", "Domains", strings.Join(t[:], " "))
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	if err := restartResolved(ctx); err != nil {
		log.Errorf("Failed to restart systemd-resolved: %v", err)
		return err
	}

	return web.JSONResponse("added", w)
}

func (d *GlobalDns) RemoveDns(ctx context.Context, w http.ResponseWriter) error {
	m, err := configfile.Load("/etc/systemd/resolved.conf")
	if err != nil {
		return err
	}

	if !validator.IsArrayEmpty(d.DnsServers) {
		s := m.GetKeySectionString("Resolve", "DNS")
		t, err := share.StringDeleteAllSlice(strings.Split(s, " "), d.DnsServers)
		if err != nil {
			return err
		}
		m.SetKeySectionString("Resolve", "DNS", strings.Join(t[:], " "))
	}
	if !validator.IsArrayEmpty(d.Domains) {
		s := m.GetKeySectionString("Resolve", "Domains")
		t, err := share.StringDeleteAllSlice(strings.Split(s, " "), d.Domains)
		if err != nil {
			return err
		}
		m.SetKeySectionString("Resolve", "Domains", strings.Join(t[:], " "))
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	if err := restartResolved(ctx); err != nil {
		log.Errorf("Failed to restart systemd-resolved: %v", err)
		return err
	}

	return web.JSONResponse("removed", w)
}
