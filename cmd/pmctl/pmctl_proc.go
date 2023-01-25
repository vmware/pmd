// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/proc"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/urfave/cli/v2"
)

type ProcArpStats struct {
	Success bool          `json:"success"`
	Message []proc.NetARP `json:"message"`
	Errors  string        `json:"errors"`
}

type ProcSysNetStats struct {
	Success bool        `json:"success"`
	Message proc.SysNet `json:"message"`
	Errors  string      `json:"errors"`
}

type ProcSysVMStats struct {
	Success bool    `json:"success"`
	Message proc.VM `json:"message"`
	Errors  string  `json:"errors"`
}

type ProcNetStats struct {
	Success bool                 `json:"success"`
	Message []net.ConnectionStat `json:"message"`
	Errors  string               `json:"errors"`
}

func parseProcSysNetArgs(args cli.Args) (*proc.SysNet, error) {
	argStrings := args.Slice()
	s := proc.SysNet{}

	for i, args := range argStrings {
		switch args {
		case "dev":
			s.Link = argStrings[i+1]
		case "property":
			s.Property = argStrings[i+1]
		case "value":
			s.Value = argStrings[i+1]
		case "path":
			if !validator.IsProcSysNetPath(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid path=%s\n", argStrings[i+1])
			}
			s.Path = argStrings[i+1]
		}
	}

	return &s, nil
}

func configureProcSysNet(args cli.Args, host string, token map[string]string) {
	url := "/api/v1/proc/sys/net"

	s, err := parseProcSysNetArgs(args)
	if err != nil {
		fmt.Printf("Failed to parse args: %v\n", err)
		return
	}

	if !validator.IsEmpty(s.Path) {
		url = url + "/" + s.Path
	}
	if !validator.IsEmpty(s.Link) {
		url = url + "/" + s.Link
	}
	if !validator.IsEmpty(s.Property) {
		url = url + "/" + s.Property
	}

	p := proc.Proc{
		Value: s.Value,
	}

	resp, err := web.DispatchSocket(http.MethodPut, host, url, token, p)
	if err != nil {
		fmt.Printf("Failed to configure sysnet '%s': %v\n", s.Property, err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to configure sysnet '%s': %v\n", s.Property, m.Errors)
	}

}

func acquireProcSysNetStats(args cli.Args, host string, token map[string]string) {
	url := "/api/v1/proc/sys/net"

	s, err := parseProcSysNetArgs(args)
	if err != nil {
		fmt.Printf("Failed to parse args: %v\n", err)
		return
	}

	if !validator.IsEmpty(s.Path) {
		url = url + "/" + s.Path
	}
	if !validator.IsEmpty(s.Link) {
		url = url + "/" + s.Link
	}
	if !validator.IsEmpty(s.Property) {
		url = url + "/" + s.Property
	}

	resp, err := web.DispatchSocket(http.MethodGet, host, url, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire sysnet info: %v\n", err)
		return
	}

	p := ProcSysNetStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !p.Success {
		fmt.Printf("Failed to fetch sysnet info: %v\n", p.Errors)
		return
	}

	if !validator.IsEmpty(p.Message.Path) {
		fmt.Printf("                 %v %v\n", color.HiBlueString("Path:"), p.Message.Path)
	}
	if !validator.IsEmpty(p.Message.Link) {
		fmt.Printf("                 %v %v\n", color.HiBlueString("Link:"), p.Message.Link)
	}
	if !validator.IsEmpty(p.Message.Property) {
		fmt.Printf("             %v %v\n", color.HiBlueString("Property:"), p.Message.Property)
	}
	if !validator.IsEmpty(p.Message.Value) {
		fmt.Printf("                %v %v\n\n", color.HiBlueString("Value:"), p.Message.Value)
	}
}

func acquireProcSysVMStats(property, host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/sys/vm/"+property, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire proc sys vm info: %v\n", err)
		return
	}

	p := ProcSysVMStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !p.Success {
		fmt.Printf("Failed to fetch proc sys vm info: %v\n", p.Errors)
		return
	}

	if !validator.IsEmpty(p.Message.Property) {
		fmt.Printf("             %v %v\n", color.HiBlueString("Property:"), p.Message.Property)
	}
	if !validator.IsEmpty(p.Message.Value) {
		fmt.Printf("                %v %v\n\n", color.HiBlueString("Value:"), p.Message.Value)
	}
}

func configureProcSysVM(property, value, host string, token map[string]string) {
	p := proc.Proc{
		Value: value,
	}

	resp, err := web.DispatchSocket(http.MethodPut, host, "/api/v1/proc/sys/vm/"+property, token, p)
	if err != nil {
		fmt.Printf("Failed to configure '%s': %v\n", property, err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to configure '%s': %v\n", property, m.Errors)
	}
}

func acquireProcSystemStats(property, host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/"+property, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire system '%s': %v\n", property, err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to acquire system '%s': %v\n", property, m.Errors)
		return
	}

	jsonData, err := json.Marshal(m.Message)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
	}
}

func acquireProcNetArpStats(host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/net/arp", token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire arp info: %v\n", err)
		return
	}

	p := ProcArpStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !p.Success {
		fmt.Printf("Failed to fetch arp info: %v\n", p.Errors)
		return
	}

	for _, arp := range p.Message {
		if !validator.IsEmpty(arp.IPAddress) {
			fmt.Printf("             %v %v\n", color.HiBlueString("IPAddress:"), arp.IPAddress)
		}
		if !validator.IsEmpty(arp.HWType) {
			fmt.Printf("                %v %v\n", color.HiBlueString("HWType:"), arp.HWType)
		}
		if !validator.IsEmpty(arp.Flags) {
			fmt.Printf("                 %v %v\n", color.HiBlueString("Flags:"), arp.Flags)
		}
		if !validator.IsEmpty(arp.HWAddress) {
			fmt.Printf("             %v %v\n", color.HiBlueString("HWAddress:"), arp.HWAddress)
		}
		if !validator.IsEmpty(arp.Mask) {
			fmt.Printf("                  %v %v\n", color.HiBlueString("Mask:"), arp.Mask)
		}
		if !validator.IsEmpty(arp.Device) {
			fmt.Printf("                %v %v\n\n", color.HiBlueString("Device:"), arp.Device)
		}
	}
}

func acquireProcNetStats(protocol, host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/netstat/"+protocol, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire netstat info: %v\n", err)
		return
	}

	p := ProcNetStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !p.Success {
		fmt.Printf("Failed to fetch netstat info: %v\n", p.Errors)
		return
	}

	jsonData, err := json.Marshal(p.Message)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
	}
}

func acquireProcessStats(pid, property, host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/process/"+pid+"/"+property, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire prcoess stats: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to fetch process stats: %v\n", m.Errors)
		return
	}

	jsonData, err := json.Marshal(m.Message)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
	}
}

func acquireProtoPidStats(pid, property, host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/protopidstat/"+pid+"/"+property, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire proto pid stats: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to fetch proto pid stats: %v\n", m.Errors)
		return
	}

	jsonData, err := json.Marshal(m.Message)
	if err != nil {
		fmt.Printf("Error: %s", err.Error())
	} else {
		fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
	}
}
