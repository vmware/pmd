// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/systemd"
)

func TestExecuteSystemdUnitCommand(t *testing.T) {
	c := systemd.UnitAction{
		Action: "start",
		Unit:   "sshd.service",
	}

	resp, err := web.DispatchSocket(http.MethodPost, "", "/api/v1/service/systemd", nil, c)
	if err != nil {
		t.Fatalf("Failed to execute systemd command: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to execute systemd command: %v\n", m.Errors)
	}
}

func TestAcquireSystemdUnitStatus(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/service/systemd/sshd.service/status", nil, nil)
	if err != nil {
		t.Fatalf("Failed to fetch unit status: %v\n", err)
	}

	u := UnitStatus{}
	if err := json.Unmarshal(resp, &u); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if u.Success {
		fmt.Printf("                 Name: %+v \n", u.Message.Name)
		fmt.Printf("          Description: %+v \n", u.Message.Description)
		fmt.Printf("              MainPid: %+v \n", u.Message.MainPid)
		fmt.Printf("            LoadState: %+v \n", u.Message.LoadState)
		fmt.Printf("          ActiveState: %+v \n", u.Message.ActiveState)
		fmt.Printf("             SubState:%+v \n", u.Message.SubState)
		fmt.Printf("        UnitFileState: %+v \n", u.Message.UnitFileState)
	} else {
		t.Fatalf(u.Errors)
	}
}
