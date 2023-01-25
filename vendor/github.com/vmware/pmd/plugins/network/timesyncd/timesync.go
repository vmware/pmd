// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package timesyncd

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/vmware/pmd/pkg/configfile"
	"github.com/vmware/pmd/pkg/share"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/systemd"
	log "github.com/sirupsen/logrus"
)

type Describe struct {
	Name             string   `json:"Name `
	IpFamily         int32    `json:"IpFamily`
	Address          string   `json:"Address"`
	SystemNTPServers []string `json:"SystemNTPServers"`
	LinkNTPServers   []string `json:"LinkNTPServers"`
}

type NTP struct {
	NTPServers []string `json:"NTPServers"`
}

func decodeJSONRequest(r *http.Request) (*NTP, error) {
	n := NTP{}
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		return nil, err
	}

	return &n, nil
}

func AcquireNTPServer(kind string, ctx context.Context) (*Describe, error) {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %v", err)
		return nil, err
	}
	defer c.Close()

	s := Describe{}
	switch kind {
	case "currentntpserver":
		s.Name, s.IpFamily, s.Address, err = c.DBusAcquireCurrentNTPServerFromTimeSync(ctx)
	case "systemntpservers":
		s.SystemNTPServers, err = c.DBusAcquireSystemNTPServersFromTimeSync(ctx)
	case "linkntpservers":
		s.LinkNTPServers, err = c.DBusAcquireLinkNTPServersFromTimeSync(ctx)
	}

	if err != nil {
		return nil, err
	}

	return &s, nil
}

func DescribeNTPServers(ctx context.Context) (*Describe, error) {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %v", err)
		return nil, err
	}
	defer c.Close()

	s := Describe{}
	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		s.Name, s.IpFamily, s.Address, err = c.DBusAcquireCurrentNTPServerFromTimeSync(ctx)
	}()

	go func() {
		defer wg.Done()
		s.SystemNTPServers, err = c.DBusAcquireSystemNTPServersFromTimeSync(ctx)
	}()

	go func() {
		defer wg.Done()
		s.LinkNTPServers, err = c.DBusAcquireLinkNTPServersFromTimeSync(ctx)
	}()

	wg.Wait()

	if err != nil {
		return nil, err
	}

	return &s, nil
}

func restartTimesyncd(ctx context.Context) error {
	u := systemd.UnitAction{
		Unit:   "systemd-timesyncd.service",
		Action: "restart",
	}

	if err := u.UnitCommands(ctx); err != nil {
		return err
	}

	return nil
}

func (n *NTP) AddNTP(ctx context.Context, w http.ResponseWriter) error {
	m, err := configfile.Load("/etc/systemd/timesyncd.conf")
	if err != nil {
		return err
	}

	if !validator.IsArrayEmpty(n.NTPServers) {
		s := m.GetKeySectionString("Time", "NTP")
		t := share.UniqueSlices(strings.Split(s, " "), n.NTPServers)
		m.SetKeySectionString("Time", "NTP", strings.Join(t[:], " "))
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	if err := restartTimesyncd(ctx); err != nil {
		log.Errorf("Failed to restart systemd-timesyncd: %v", err)
		return err
	}

	return web.JSONResponse("added", w)
}

func (n *NTP) RemoveNTP(ctx context.Context, w http.ResponseWriter) error {
	m, err := configfile.Load("/etc/systemd/timesyncd.conf")
	if err != nil {
		return err
	}

	if !validator.IsArrayEmpty(n.NTPServers) {
		s := m.GetKeySectionString("Time", "NTP")
		t, err := share.StringDeleteAllSlice(strings.Split(s, " "), n.NTPServers)
		if err != nil {
			return err
		}
		m.SetKeySectionString("Time", "NTP", strings.Join(t[:], " "))
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	if err := restartTimesyncd(ctx); err != nil {
		log.Errorf("Failed to restart systemd-timesyncd: %v", err)
		return err
	}

	return web.JSONResponse("removed", w)
}
