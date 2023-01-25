// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/fatih/color"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/management/sysctl"
)

func TestSysctlConfigUpdate(t *testing.T) {
	s := sysctl.Sysctl{
		Key:   "fs.file-max",
		Value: "65536",
		Apply: true,
	}

	resp, err := web.DispatchSocket(http.MethodPost, "", "/api/v1/system/sysctl/update", nil, s)
	if err != nil {
		t.Fatalf("Failed to update sysctl configuration: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to update sysctl configuration: %v\n", m.Errors)
	}

}

func TestAcquireSysctlKeyStatus(t *testing.T) {
	s := sysctl.Sysctl{
		Key: "fs.file-max",
	}

	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/sysctl/status", nil, s)
	if err != nil {
		t.Fatalf("Failed to acquire sysctl status: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if m.Success {
		fmt.Printf("             %v %v\n", color.HiBlueString(s.Key+": "), m.Message)
	} else {
		t.Fatalf(m.Errors)
	}

}

func TestSysctlConfigRemove(t *testing.T) {
	s := sysctl.Sysctl{
		Key:   "fs.file-max",
		Apply: true,
	}

	resp, err := web.DispatchSocket(http.MethodDelete, "", "/api/v1/system/sysctl/remove", nil, s)
	if err != nil {
		t.Fatalf("Failed to remove sysctl configuration: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to remove sysctl configuration: %v\n", m.Errors)
	}

}

func TestSysctlConfigLoad(t *testing.T) {
	s := sysctl.Sysctl{
		Apply: true,
	}

	resp, err := web.DispatchSocket(http.MethodPost, "", "/api/v1/system/sysctl/load", nil, s)
	if err != nil {
		t.Fatalf("Failed to load sysctl configuration: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to load sysctl configuration: %v\n", m.Errors)
	}

}

func TestAcquireSysctlStatus(t *testing.T) {
	s := sysctl.Sysctl{
		Pattern: "",
	}

	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/sysctl/statusall", nil, s)
	if err != nil {
		t.Fatalf("Failed to acquire sysctl status: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if m.Success {
		jsonStr, err := json.Marshal(m.Message)
		if err != nil {
			t.Fatalf("Failed to acquire sysctl status: %v\n", err.Error())
		} else {
			fmt.Printf("%v\n", color.HiBlueString(string(jsonStr)))
		}
	} else {
		t.Fatalf(m.Errors)
	}

}
