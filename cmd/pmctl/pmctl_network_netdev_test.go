// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/network/networkd"
	"github.com/vishvananda/netlink"
)

func configureNetDev(t *testing.T, n networkd.NetDev) error {
	var resp []byte
	var err error

	resp, err = web.DispatchSocket(http.MethodPost, "", "/api/v1/network/networkd/netdev/configure", nil, n)
	if err != nil {
		t.Fatalf("Failed to configure netdev: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to configure netdev: %v\n", j.Errors)
	}

	return nil
}

func TestNetDevCreateVLan(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	n := networkd.NetDev{
		Name:  "vlan99",
		Kind:  "vlan",
		Links: []string{"test99"},
		VLanSection: networkd.VLan{
			Id: 10,
		},
	}

	if err := configureNetDev(t, n); err != nil {
		t.Fatalf("Failed to create VLan: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("vlan99") {
		t.Fatalf("Failed to create vlan='vlan99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "vlan99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("vlan99", "vlan")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of vlan='vlan99'")
	}

	if m.GetKeySectionString("NetDev", "Kind") != "vlan" {
		t.Fatalf("Vlan kind is not 'vlan' in .netdev file of vlan='vlan99'")
	}

	if m.GetKeySectionUint("VLAN", "Id") != 10 {
		t.Fatalf("Invalid Vlan Id in .netdev file of vlan='vlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("vlan99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of vlan='vlan99'")
	}

	if m.GetKeySectionString("Match", "Name") != "vlan99" {
		t.Fatalf("Invalid netdev name in .network file of vlan='vlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "VLAN") != "vlan99" {
		t.Fatalf("Failed to parse .network file of test99")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}

func TestNetDevCreateBond(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test98"}})
	defer removeLink(t, "test99")
	defer removeLink(t, "test98")

	n := networkd.NetDev{
		Name:  "bond99",
		Kind:  "bond",
		Links: []string{"test99", "test98"},
		BondSection: networkd.Bond{
			Mode: "balance-rr",
		},
	}

	if err := configureNetDev(t, n); err != nil {
		t.Fatalf("Failed to create Bond: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("bond99") {
		t.Fatalf("Failed to create bond='bond99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "bond99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("bond99", "bond")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of bond='bond99'")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("NetDev", "Kind") != "bond" {
		t.Fatalf("Bond kind is not 'bond' in .netdev file of bond='bond99'")
	}

	if m.GetKeySectionString("Bond", "Mode") != "balance-rr" {
		t.Fatalf("Invalid bond mode in .netdev file of bond='bond99'")
	}

	m1, err := networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m1.Path)

	if m1.GetKeySectionString("Network", "Bond") != "bond99" {
		t.Fatalf("Failed to parse Bond=bond99 in .network file")
	}

	m2, err := networkd.CreateOrParseNetworkFile("test98")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m2.Path)

	if m2.GetKeySectionString("Network", "Bond") != "bond99" {
		t.Fatalf("Failed to parse Bond=bond99 in .network file")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}

func TestNetDevCreateVXLan(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	n := networkd.NetDev{
		Name:  "vxlan99",
		Kind:  "vxlan",
		Links: []string{"test99"},
		VxLanSection: networkd.VxLan{
			VNI:             "100",
			Remote:          "192.168.1.3",
			Local:           "192.168.1.2",
			DestinationPort: "7777",
		},
	}

	if err := configureNetDev(t, n); err != nil {
		t.Fatalf("Failed to create VxLan: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("vxlan99") {
		t.Fatalf("Failed to create vxlan='vxlan99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "vxlan99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("vxlan99", "vxlan")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of vxlan='vxlan99'")
	}

	if m.GetKeySectionString("NetDev", "Kind") != "vxlan" {
		t.Fatalf("Vxlan kind is not 'vxlan' in .netdev file of vxlan='vxlan99'")
	}

	if m.GetKeySectionUint("VXLAN", "VNI") != 100 {
		t.Fatalf("Invalid Vxlan VNI in .netdev file of vxlan='vxlan99'")
	}

	if m.GetKeySectionString("VXLAN", "Remote") != "192.168.1.3" {
		t.Fatalf("Invalid Vxlan Remote in .netdev file of vxlan='vxlan99'")
	}

	if m.GetKeySectionString("VXLAN", "Local") != "192.168.1.2" {
		t.Fatalf("Invalid Vxlan Local in .netdev file of vxlan='vxlan99'")
	}
	if m.GetKeySectionUint("VXLAN", "DestinationPort") != 7777 {
		t.Fatalf("Invalid Vxlan DestinationPort in .netdev file of vxlan='vxlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("vxlan99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of vxlan='vxlan99'")
	}

	if m.GetKeySectionString("Match", "Name") != "vxlan99" {
		t.Fatalf("Invalid netdev name in .network file of vxlan='vxlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "VXLAN") != "vxlan99" {
		t.Fatalf("Failed to parse .network file of test99")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}

func TestNetDevCreateBridge(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test98"}})
	defer removeLink(t, "test99")
	defer removeLink(t, "test98")

	n := networkd.NetDev{
		Name:  "bridge99",
		Kind:  "bridge",
		Links: []string{"test99", "test98"},
		BridgeSection: networkd.Bridge{
			STP: "yes",
		},
	}

	if err := configureNetDev(t, n); err != nil {
		fmt.Println(err)
		t.Fatalf("Failed to create Bridge: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("bridge99") {
		t.Fatalf("Failed to create bridge='bridge99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "bridge99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("bridge99", "bridge")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of bridge='bridge99'")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("NetDev", "Kind") != "bridge" {
		t.Fatalf("Bridge kind is not 'bridge' in .netdev file of bridge='bridge99'")
	}

	if m.GetKeySectionString("Bridge", "STP") != "yes" {
		t.Fatalf("Invalid bridge STP in .netdev file of bridge='bridge99'")
	}

	m1, err := networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m1.Path)

	if m1.GetKeySectionString("Network", "Bridge") != "bridge99" {
		t.Fatalf("Failed to parse Bridge=bridge99 in .network file")
	}

	m2, err := networkd.CreateOrParseNetworkFile("test98")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m2.Path)

	if m2.GetKeySectionString("Network", "Bridge") != "bridge99" {
		t.Fatalf("Failed to parse Bridge=bridge99 in .network file")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}

func TestNetDevCreateMACVLan(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	n := networkd.NetDev{
		Name:  "macvlan99",
		Kind:  "macvlan",
		Links: []string{"test99"},
		MacVLanSection: networkd.MacVLan{
			Mode: "bridge",
		},
	}

	if err := configureNetDev(t, n); err != nil {
		t.Fatalf("Failed to create MacVLan: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("macvlan99") {
		t.Fatalf("Failed to create macvlan='macvlan99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "macvlan99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("macvlan99", "macvlan")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of macvlan='macvlan99'")
	}

	if m.GetKeySectionString("NetDev", "Kind") != "macvlan" {
		t.Fatalf("MacVLan kind is not 'macvlan' in .netdev file of macvlan='macvlan99'")
	}

	if m.GetKeySectionString("MACVLAN", "Mode") != "bridge" {
		t.Fatalf("Invalid MacVLan mode .netdev file of macvlan='macvlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("macvlan99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of macvlan='macvlan99'")
	}

	if m.GetKeySectionString("Match", "Name") != "macvlan99" {
		t.Fatalf("Invalid netdev name in .network file of macvlan='macvlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "MACVLAN") != "macvlan99" {
		t.Fatalf("Failed to parse .network file of test99")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}

func TestNetDevCreateMACVTap(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	n := networkd.NetDev{
		Name:  "macvtap99",
		Kind:  "macvtap",
		Links: []string{"test99"},
		MacVLanSection: networkd.MacVLan{
			Mode: "bridge",
		},
	}

	if err := configureNetDev(t, n); err != nil {
		t.Fatalf("Failed to create MacVTap: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("macvtap99") {
		t.Fatalf("Failed to create macvtap='macvtap99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "macvtap99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("macvtap99", "macvtap")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of macvtap='macvtap99'")
	}

	if m.GetKeySectionString("NetDev", "Kind") != "macvtap" {
		t.Fatalf("MacVTap kind is not 'macvtap' in .netdev file of macvtap='macvtap99'")
	}

	if m.GetKeySectionString("MACVTAP", "Mode") != "bridge" {
		t.Fatalf("Invalid MacVTap mode .netdev file of macvtap='macvtap99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("macvtap99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of macvtap='macvtap99'")
	}

	if m.GetKeySectionString("Match", "Name") != "macvtap99" {
		t.Fatalf("Invalid netdev name in .network file of macvtap='macvtap99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "MACVTAP") != "macvtap99" {
		t.Fatalf("Failed to parse .network file of test99")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}

func TestNetDevCreateIPVLan(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	n := networkd.NetDev{
		Name:  "ipvlan99",
		Kind:  "ipvlan",
		Links: []string{"test99"},
		IpVLanSection: networkd.IpVLan{
			Mode: "l2",
		},
	}

	if err := configureNetDev(t, n); err != nil {
		t.Fatalf("Failed to create IPVLan: %v\n", err)
	}

	time.Sleep(time.Second * 5)

	if !validator.LinkExists("ipvlan99") {
		t.Fatalf("Failed to create ipvlan='ipvlan99'")
	}

	s, _ := system.ExecAndCapture("ip", "-d", "link", "show", "ipvlan99")
	fmt.Println(s)

	m, _, err := networkd.CreateOrParseNetDevFile("ipvlan99", "ipvlan")
	if err != nil {
		t.Fatalf("Failed to parse .netdev file of ipvlan='ipvlan99'")
	}

	if m.GetKeySectionString("NetDev", "Kind") != "ipvlan" {
		t.Fatalf("IPVLap kind is not 'ipvlan' in .netdev file of ipvlan='ipvlan99'")
	}

	if m.GetKeySectionString("IPVLAN", "Mode") != "l2" {
		t.Fatalf("Invalid IPVLan mode .netdev file of ipvlan='ipvlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("ipvlan99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of ipvlan='ipvlan99'")
	}

	if m.GetKeySectionString("Match", "Name") != "ipvlan99" {
		t.Fatalf("Invalid netdev name in .network file of ipvlan='ipvlan99'")
	}

	m, err = networkd.CreateOrParseNetworkFile("test99")
	if err != nil {
		t.Fatalf("Failed to parse .network file of test99")
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "IPVLAN") != "ipvlan99" {
		t.Fatalf("Failed to parse .network file of test99")
	}

	if err := networkd.RemoveNetDev(n.Name, n.Kind); err != nil {
		t.Fatalf("Failed to remove .network file='%v'", err)
	}
}
