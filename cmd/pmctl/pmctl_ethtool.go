// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/vmware/pmd/pkg/web"
)

func acquireEthtoolStatus(link, host string, token map[string]string) {
	url := "/api/v1/network/ethtool" + "/" + link

	resp, err := web.DispatchSocket(http.MethodGet, host, url, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire ethtool status: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to acquire ethtool status: %v\n", m.Errors)
		return
	}

	fmt.Println(m.Message)
}

func acquireEthtoolActionStatus(link, action, host string, token map[string]string) {
	url := "/api/v1/network/ethtool" + "/" + link + "/" + action

	resp, err := web.DispatchSocket(http.MethodGet, host, url, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire ethtool status: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to acquire ethtool status: %v\n", m.Errors)
		return
	}

	jsonData, err := json.MarshalIndent(m.Message, "", "    ")
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
	}
}
