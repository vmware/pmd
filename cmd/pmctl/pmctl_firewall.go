// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/google/nftables"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/network/firewall"
	"github.com/urfave/cli/v2"
)

type tableStats struct {
	Success bool                       `json:"success"`
	Message map[string]*nftables.Table `json:"message"`
	Errors  string                     `json:"errors"`
}

type chainStats struct {
	Success bool                       `json:"success"`
	Message map[string]*nftables.Chain `json:"message"`
	Errors  string                     `json:"errors"`
}

func parseNFTTable(args cli.Args) (*firewall.Nft, error) {
	argStrings := args.Slice()
	n := firewall.Nft{}

	for i, args := range argStrings {
		switch args {
		case "family":
			if !validator.IsNFTFamily(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid family: '%s'", argStrings[i+1])
			}
			n.Table.Family = argStrings[i+1]
		case "name":
			if validator.IsEmpty(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid name: '%s'", argStrings[i+1])
			}
			n.Table.Name = argStrings[i+1]
		}
	}

	return &n, nil
}

func parseNFTChain(args cli.Args) (*firewall.Nft, error) {
	argStrings := args.Slice()
	n := firewall.Nft{}

	for i, args := range argStrings {
		switch args {
		case "name":
			if validator.IsEmpty(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid name: '%s'", argStrings[i+1])
			}
			n.Chain.Name = argStrings[i+1]
		case "table":
			if validator.IsEmpty(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid table: '%s'", argStrings[i+1])
			}
			n.Chain.Table = argStrings[i+1]
		case "family":
			if !validator.IsNFTFamily(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid family: '%s'", argStrings[i+1])
			}
			n.Chain.Family = argStrings[i+1]
		case "hook":
			if !validator.IsNFTChainHook(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid hook: '%s'", argStrings[i+1])
			}
			n.Chain.Hook = argStrings[i+1]
		case "type":
			if !validator.IsNFTChainType(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid type: '%s'", argStrings[i+1])
			}
			n.Chain.Type = argStrings[i+1]
		case "priority":
			if validator.IsEmpty(argStrings[i+1]) {
				return nil, fmt.Errorf("missing priority: '%s'", argStrings[i+1])
			}
			n.Chain.Priority = argStrings[i+1]
		case "policy":
			if !validator.IsNFTChainPolicy(argStrings[i+1]) {
				return nil, fmt.Errorf("invalid policy: '%s'", argStrings[i+1])
			}
			n.Chain.Policy = argStrings[i+1]
		}
	}

	return &n, nil
}

func networkAddNFTTable(args cli.Args, host string, token map[string]string) {
	n, err := parseNFTTable(args)
	if err != nil {
		fmt.Printf("Failed to parse table: %v", err)
		return
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/network/firewall/nft/table/add", token, n)
	if err != nil {
		fmt.Printf("Failed to add table: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to add table %v\n", m.Errors)
	}
}

func networkShowNFTTable(args cli.Args, host string, token map[string]string) {
	n, err := parseNFTTable(args)
	if err != nil {
		fmt.Printf("Failed to parse table: %v\n", err)
		return
	}

	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/network/firewall/nft/table/show", token, n)
	if err != nil {
		fmt.Printf("Failed to show table: %v\n", err)
		return
	}

	ts := tableStats{}
	if err := json.Unmarshal(resp, &ts); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !ts.Success {
		fmt.Printf("Failed to acquire table: %v\n", ts.Errors)
	}

	for _, v := range ts.Message {
		fmt.Printf("             %v %v\n", color.HiBlueString("Table:"), v.Name)
		fmt.Printf("            %v %v\n\n", color.HiBlueString("Family:"), v.Family)
	}
}

func networkDeleteNFTTable(args cli.Args, host string, token map[string]string) {
	n, err := parseNFTTable(args)
	if err != nil {
		fmt.Printf("Failed to parse table: %v\n", err)
		return
	}

	resp, err := web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/firewall/nft/table/remove", token, n)
	if err != nil {
		fmt.Printf("Failed to delete table: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to delete table %v\n", m.Errors)
	}
}

func networkSaveNFT(host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodPut, host, "/api/v1/network/firewall/nft/save", token, nil)
	if err != nil {
		fmt.Printf("Failed to save table: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to save table: %v\n", m.Errors)
	}
}

func networkAddNFTChain(args cli.Args, host string, token map[string]string) {
	n, err := parseNFTChain(args)
	if err != nil {
		fmt.Printf("Failed to parse chain: %v", err)
		return
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/network/firewall/nft/chain/add", token, n)
	if err != nil {
		fmt.Printf("Failed to add chain: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to add chain: %v\n", m.Errors)
	}
}

func networkDeleteNFTChain(args cli.Args, host string, token map[string]string) {
	n, err := parseNFTChain(args)
	if err != nil {
		fmt.Printf("Failed to parse chain: %v", err)
		return
	}

	resp, err := web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/firewall/nft/chain/remove", token, n)
	if err != nil {
		fmt.Printf("Failed to remove chain: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove chain: %v\n", m.Errors)
	}
}

func networkShowNFTChain(args cli.Args, host string, token map[string]string) {
	n, err := parseNFTChain(args)
	if err != nil {
		fmt.Printf("Failed to parse chain: %v", err)
		return
	}

	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/network/firewall/nft/chain/show", token, n)
	if err != nil {
		fmt.Printf("Failed to show chain: %v\n", err)
		return
	}

	cs := chainStats{}
	if err := json.Unmarshal(resp, &cs); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !cs.Success {
		fmt.Printf("Failed to acquire chain: %v\n", cs.Errors)
	}

	for _, v := range cs.Message {
		fmt.Printf("               %v %v\n", color.HiBlueString("Table:"), v.Table.Name)
		fmt.Printf("              %v %v\n", color.HiBlueString("Family:"), v.Table.Family)
		fmt.Printf("               %v %v\n", color.HiBlueString("Chain:"), v.Name)
		fmt.Printf("                %v %v\n", color.HiBlueString("Hook:"), v.Hooknum)
		fmt.Printf("                %v %v\n", color.HiBlueString("Type:"), v.Type)
		fmt.Printf("              %v %v\n", color.HiBlueString("Policy:"), *v.Policy)
		fmt.Printf("            %v %v\n\n", color.HiBlueString("Priority:"), v.Priority)
	}
}

func networkRunNFT(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := firewall.Nft{
		Command: argStrings,
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/network/firewall/nft/run", token, n)
	if err != nil {
		fmt.Printf("Failed to run nft command: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to run nft command: %v\n", m.Errors)
		return
	}

	fmt.Printf("%v", m.Message)
}
