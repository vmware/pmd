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
	"github.com/vishvananda/netlink"
)

func TestAcquireEthtoolStatus(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/network/ethtool/test99", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire ethtool info: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if m.Success {
		fmt.Println(m.Message)
	} else {
		t.Fatalf(m.Errors)
	}
}

func TestAcquireEthtoolActionStatus(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/network/ethtool/test99/features", nil, nil)
	if err != nil {
		fmt.Printf("Failed to acquire ethtool features status: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if m.Success {
		jsonData, _ := json.MarshalIndent(m.Message, "", "    ")
		fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
	} else {
		t.Fatalf(m.Errors)
	}

}
