// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/fatih/color"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/proc"
	"github.com/vishvananda/netlink"
)

func TestConfigureProcSysNet(t *testing.T) {
	p := proc.Proc{
		Value: "64",
	}

	resp, err := web.DispatchSocket(http.MethodPut, "", "/api/v1/proc/sys/net/core/dev_weight", nil, p)
	if err != nil {
		t.Fatalf("Failed to configure sysnet: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to configure sysnet: %v\n", m.Errors)
	}
}

func TestAcquireProcSysNetStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/sys/net/core/dev_weight", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire sysnet info: %v\n", err)
	}

	p := ProcSysNetStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if p.Success {
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
	} else {
		t.Fatalf(p.Errors)
	}
}

func TestConfigureLinkProcSysNet(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	p := proc.Proc{
		Value: "1300",
	}

	resp, err := web.DispatchSocket(http.MethodPut, "", "/api/v1/proc/sys/net/ipv6/test99/mtu", nil, p)
	if err != nil {
		t.Fatalf("Failed to configure sysnet: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to configure sysnet: %v\n", m.Errors)
	}
}

func TestAcquireLinkProcSysNetStats(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/sys/net/ipv6/test99/mtu", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire sysnet info: %v\n", err)
	}

	p := ProcSysNetStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if p.Success {
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
	} else {
		t.Fatalf(p.Errors)
	}
}

func TestConfigureProcSysVM(t *testing.T) {
	p := proc.Proc{
		Value: "3",
	}

	resp, err := web.DispatchSocket(http.MethodPut, "", "/api/v1/proc/sys/vm/page-cluster", nil, p)
	if err != nil {
		t.Fatalf("Failed to configure: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to configure: %v\n", m.Errors)
	}
}

func TestAcquireProcSysVMStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/sys/vm/page-cluster", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire proc sys vm info: %v\n", err)
	}

	p := ProcSysVMStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if p.Success {
		if !validator.IsEmpty(p.Message.Property) {
			fmt.Printf("             %v %v\n", color.HiBlueString("Property:"), p.Message.Property)
		}
		if !validator.IsEmpty(p.Message.Value) {
			fmt.Printf("                %v %v\n\n", color.HiBlueString("Value:"), p.Message.Value)
		}
	} else {
		t.Fatalf(p.Errors)
	}
}

func TestAcquireProcSystemStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/cpuinfo", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire system cpuinfo: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if m.Success {
		jsonData, err := json.Marshal(m.Message)
		if err != nil {
			t.Fatalf(err.Error())
		} else {
			fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
		}
	} else {
		t.Fatalf(m.Errors)
	}
}

func TestAcquireProcNetArpStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/net/arp", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire arp info: %v\n", err)
	}

	p := ProcArpStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if p.Success {
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
	} else {
		t.Fatalf(p.Errors)
	}

}

func TestAcquireProcNetStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/netstat/tcp", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire netstat info: %v\n", err)
	}

	p := ProcNetStats{}
	if err := json.Unmarshal(resp, &p); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if p.Success {
		jsonData, err := json.Marshal(p.Message)
		if err != nil {
			t.Fatalf(err.Error())
		} else {
			fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
		}
	} else {
		t.Fatalf(p.Errors)
	}
}

func TestAcquireProcessStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/process/"+strconv.Itoa(os.Getpid())+"/pid-memory-percent", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire prcoess stats: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if m.Success {
		jsonData, err := json.Marshal(m.Message)
		if err != nil {
			t.Fatalf(err.Error())
		} else {
			fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
		}
	} else {
		t.Fatalf(m.Errors)
	}
}

func TestAcquireProtoPidStats(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/proc/protopidstat/"+strconv.Itoa(os.Getpid())+"/tcp", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire proto pid stats: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if m.Success {
		jsonData, err := json.Marshal(m.Message)
		if err != nil {
			t.Fatalf(err.Error())
		} else {
			fmt.Printf("%v\n", color.HiBlueString(string(jsonData)))
		}
	} else {
		t.Fatalf(m.Errors)
	}
}
