// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/management/hostname"
)

func TestSetHostname(t *testing.T) {
	h := hostname.Hostname{
		PrettyHostname: "DemoHostName",
	}

	resp, err := web.DispatchSocket(http.MethodPost, "", "/api/v1/system/hostname/update", nil, h)
	if err != nil {
		t.Fatalf("Failed to set hostname: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to set hostname: %v\n", m.Errors)
	}
}

func TestAcquireSystemStatus(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/describe", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire system info: %v\n", err)
	}

	h := SystemDescribe{}
	if err := json.Unmarshal(resp, &h); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if h.Success {
		displayHostname(h.Message.Hostname)
		displayTimeDate(h.Message.TimeDate)
		displaySystemd(h.Message.Systemd)
		displayNetworkState(h.Message.NetworkDescribe)
		displayNetworkAddresses(h.Message.Addresses)
		displayRoutes(h.Message.Routes)
		displayHostInfo(h.Message.HostInfo, h.Message.UserStat)
		displayVMStat(h.Message.VirtualMemoryStat)
	} else {
		t.Fatalf(h.Errors)
	}

}
