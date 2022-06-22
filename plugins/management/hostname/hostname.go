// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package hostname

import (
	"context"
	"net/http"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
)

type Hostname struct {
	Hostname          string `json:"Hostname"`
	PrettyHostname    string `json:"PrettyHostname"`
	StaticHostname    string `json:"StaticHostname"`
	TransientHostname string `json:"TransientHostname"`
}

type Describe struct {
	Chassis                   string `json:"Chassis"`
	DefaultHostname           string `json:"DefaultHostname"`
	Deployment                string `json:"Deployment"`
	HardwareModel             string `json:"HardwareModel"`
	HardwareVendor            string `json:"HardwareVendor"`
	Hostname                  string `json:"Hostname"`
	HostnameSource            string `json:"HostnameSource"`
	IconName                  string `json:"IconName"`
	KernelName                string `json:"KernelName"`
	KernelRelease             string `json:"KernelRelease"`
	KernelVersion             string `json:"KernelVersion"`
	Location                  string `json:"Location"`
	OperatingSystemCPEName    string `json:"OperatingSystemCPEName"`
	OperatingSystemHomeURL    string `json:"OperatingSystemHomeURL"`
	OperatingSystemPrettyName string `json:"OperatingSystemPrettyName"`
	PrettyHostname            string `json:"PrettyHostname"`
	ProductUUID               string `json:"ProductUUID"`
	StaticHostname            string `json:"StaticHostname"`
}

func (h *Hostname) Update(ctx context.Context, w http.ResponseWriter) error {
	conn, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %v", err)
		return err
	}
	defer conn.Close()

	host := Hostname{}
	var wg sync.WaitGroup

	sz := 0
	if !validator.IsEmpty(h.PrettyHostname) {
		sz++
	}
	if !validator.IsEmpty(h.StaticHostname) {
		sz++
	}
	if !validator.IsEmpty(h.TransientHostname) {
		sz++
	}

	wg.Add(sz)

	if !validator.IsEmpty(h.PrettyHostname) {
		go func() {
			defer wg.Done()
			if err := conn.DBusExecuteMethod(ctx, "SetPrettyHostname", h.PrettyHostname); err == nil {
				host.PrettyHostname = h.PrettyHostname
			}
		}()
	}

	if !validator.IsEmpty(h.StaticHostname) {
		go func() {
			defer wg.Done()
			if err := conn.DBusExecuteMethod(ctx, "SetStaticHostname", h.StaticHostname); err != nil {
				host.StaticHostname = h.StaticHostname
			}
		}()
	}

	if !validator.IsEmpty(h.TransientHostname) {
		go func() {
			defer wg.Done()
			if err := conn.DBusExecuteMethod(ctx, "SetHostname", h.TransientHostname); err != nil {
				host.TransientHostname = h.TransientHostname
			}
		}()
	}

	wg.Wait()

	return web.JSONResponse(host, w)
}

func MethodDescribe(ctx context.Context) (*Describe, error) {
	conn, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %v", err)
		return nil, err
	}
	defer conn.Close()

	desc, err := conn.DBusDescribe(ctx)
	if err != nil {
		return nil, err
	}

	return desc, nil
}
