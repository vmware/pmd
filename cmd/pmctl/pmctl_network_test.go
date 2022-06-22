// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vmware/pmd/pkg/configfile"
	"github.com/vmware/pmd/pkg/share"
	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/network/networkd"
	"github.com/vmware/pmd/plugins/network/resolved"
	"github.com/vishvananda/netlink"
)

func setupLink(t *testing.T, link netlink.Link) {
	if err := netlink.LinkAdd(link); err != nil && err.Error() != "file exists" {
		t.Fatal(err)
	}

	if !validator.LinkExists(link.Attrs().Name) {
		t.Fatal("link does not exists")
	}
}

func removeLink(t *testing.T, link string) {
	l, err := netlink.LinkByName(link)
	if err != nil {
		t.Fatal(err)
	}

	netlink.LinkDel(l)
}

func configureNetwork(t *testing.T, n networkd.Network) (*configfile.Meta, error) {
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodPost, "", "/api/v1/network/networkd/network/configure", nil, n)
	if err != nil {
		t.Fatalf("Failed to configure network: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to configure network: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)
	link, err := netlink.LinkByName("test99")
	network, err := networkd.ParseLinkNetworkFile(link.Attrs().Index)
	if err != nil {
		t.Fatalf("Failed to parse link network file: %v\n", err)
	}

	m, err := configfile.Load(network)

	return m, err
}

func removeNetwork(t *testing.T, n networkd.Network) (*configfile.Meta, error) {
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodDelete, "", "/api/v1/network/networkd/network/remove", nil, n)
	if err != nil {
		t.Fatalf("Failed to remove network: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to remove network: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)
	link, err := netlink.LinkByName("test99")
	network, err := networkd.ParseLinkNetworkFile(link.Attrs().Index)
	if err != nil {
		t.Fatalf("Failed to parse link network file: %v\n", err)
	}

	m, err := configfile.Load(network)
	defer os.Remove(m.Path)

	return m, err
}

func TestNetworkAddGlobalDns(t *testing.T) {
	s := []string{"8.8.8.8", "8.8.4.4", "8.8.8.1", "8.8.8.2"}
	n := resolved.GlobalDns{
		DnsServers: s,
	}
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodPost, "", "/api/v1/network/resolved/add", nil, n)
	if err != nil {
		t.Fatalf("Failed to add global Dns server: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to add Dns servers: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)

	m, err := configfile.Load("/etc/systemd/resolved.conf")
	if err != nil {
		t.Fatalf("Failed to load resolved.conf: %v\n", err)
	}

	dns := m.GetKeySectionString("Resolve", "DNS")
	for _, d := range s {
		if !share.StringContains(strings.Split(dns, " "), d) {
			t.Fatalf("Failed")
		}
	}
}

func TestNetworkRemoveGlobalDns(t *testing.T) {
	TestNetworkAddGlobalDns(t)
	s := []string{"8.8.8.8", "8.8.4.4"}
	n := resolved.GlobalDns{
		DnsServers: s,
	}
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodDelete, "", "/api/v1/network/resolved/remove", nil, n)
	if err != nil {
		t.Fatalf("Failed to add global Dns servers: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to configure Dns: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)

	m, err := configfile.Load("/etc/systemd/resolved.conf")
	if err != nil {
		t.Fatalf("Failed to load resolved.conf: %v\n", err)
	}

	dns := m.GetKeySectionString("Resolve", "DNS")
	for _, d := range s {
		if share.StringContains(strings.Split(dns, " "), d) {
			t.Fatalf("Failed")
		}
	}
}

func TestNetworkAddGlobalDomain(t *testing.T) {
	s := []string{"test1.com", "test2.com", "test3.com", "test4.com"}
	n := resolved.GlobalDns{
		Domains: s,
	}
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodPost, "", "/api/v1/network/resolved/add", nil, n)
	if err != nil {
		t.Fatalf("Failed to add global domain: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to configure domain: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)

	m, err := configfile.Load("/etc/systemd/resolved.conf")
	if err != nil {
		t.Fatalf("Failed to load resolved.conf: %v\n", err)
	}

	domains := m.GetKeySectionString("Resolve", "Domains")
	for _, d := range s {
		if !share.StringContains(strings.Split(domains, " "), d) {
			t.Fatalf("Failed")
		}
	}
}

func TestNetworkRemoveGlobalDomain(t *testing.T) {
	TestNetworkAddGlobalDomain(t)
	s := []string{"test1.com", "test2.com"}
	n := resolved.GlobalDns{
		Domains: s,
	}
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodDelete, "", "/api/v1/network/resolved/remove", nil, n)
	if err != nil {
		t.Fatalf("Failed to add global domain: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to remove domain: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)

	m, err := configfile.Load("/etc/systemd/resolved.conf")
	if err != nil {
		t.Fatalf("Failed to load resolved.conf: %v\n", err)
	}

	domains := m.GetKeySectionString("Resolve", "Domains")
	for _, d := range s {
		if share.StringContains(strings.Split(domains, " "), d) {
			t.Fatalf("Failed")
		}
	}
}

func TestNetworkAddLinkDomain(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	s := []string{"test1.com", "test2.com", "test3.com", "test4.com"}
	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			Domains: s,
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure link domain: %v\n", err)
	}
	defer os.Remove(m.Path)

	domains := m.GetKeySectionString("Network", "Domains")
	for _, d := range s {
		if !share.StringContains(strings.Split(domains, " "), d) {
			t.Fatalf("Failed")
		}
	}
}

func TestNetworkRemoveLinkDomain(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	s := []string{"test1.com", "test2.com", "test3.com", "test4.com"}
	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			Domains: s,
		},
	}

	_, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to add link domain: %v\n", err)
	}

	s = []string{"test3.com", "test4.com"}
	n = networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			Domains: s,
		},
	}

	m, err := removeNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to remove link domain: %v\n", err)
	}

	domains := m.GetKeySectionString("Network", "Domains")
	for _, d := range s {
		if share.StringContains(strings.Split(domains, " "), d) {
			t.Fatalf("Failed")
		}
	}
}

func TestNetworkDHCP(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			DHCP: "ipv4",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCP: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "DHCP") != "ipv4" {
		t.Fatalf("Failed to set DHCP")
	}
}

func TestNetworkLinkLocalAddressing(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			LinkLocalAddressing: "ipv4",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure LinkLocalAddressing: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "LinkLocalAddressing") != "ipv4" {
		t.Fatalf("Failed to set LinkLocalAddressing")
	}
}

func TestNetworkMulticastDNS(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			MulticastDNS: "resolve",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure MulticastDNS: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "MulticastDNS") != "resolve" {
		t.Fatalf("Failed to set MulticastDNS")
	}
}

func TestNetworkIPv6AcceptRA(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			IPv6AcceptRA: "no",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure IPv6AcceptRA: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "IPv6AcceptRA") != "no" {
		t.Fatalf("Failed to set IPv6AcceptRA")
	}
}

func TestNetworkDHCP4ClientIdentifier(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv4Section: networkd.DHCPv4Section{
			ClientIdentifier: "duid",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCP4ClientIdentifier: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv4", "ClientIdentifier") != "duid" {
		t.Fatalf("Failed to set ClientIdentifier")
	}
}

func TestNetworkDHCPIAID(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv4Section: networkd.DHCPv4Section{
			IAID: "8765434",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPIAID: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv4", "IAID") != "8765434" {
		t.Fatalf("Failed to set IAID")
	}
}

func TestNetworkRoute(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		RouteSections: []networkd.RouteSection{
			{
				Gateway:         "192.168.0.1",
				GatewayOnlink:   "no",
				Source:          "192.168.1.15/24",
				Destination:     "192.168.10.10/24",
				PreferredSource: "192.168.8.9",
				Table:           "1234",
				Scope:           "link",
			},
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Route: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Route", "Gateway") != "192.168.0.1" {
		t.Fatalf("Failed to set Gateway")
	}
	if m.GetKeySectionString("Route", "GatewayOnlink") != "no" {
		t.Fatalf("Failed to set GatewayOnlink")
	}
	if m.GetKeySectionString("Route", "Source") != "192.168.1.15/24" {
		t.Fatalf("Failed to set Source")
	}
	if m.GetKeySectionString("Route", "Destination") != "192.168.10.10/24" {
		t.Fatalf("Failed to set Destination")
	}
	if m.GetKeySectionString("Route", "PreferredSource") != "192.168.8.9" {
		t.Fatalf("Failed to set PreferredSource")
	}
	if m.GetKeySectionString("Route", "Table") != "1234" {
		t.Fatalf("Failed to set Table")
	}
	if m.GetKeySectionString("Route", "Scope") != "link" {
		t.Fatalf("Failed to set Scope")
	}
}

func TestNetworkAddress(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		AddressSections: []networkd.AddressSection{
			{
				Address: "192.168.1.15/24",
				Peer:    "192.168.10.10/24",
				Label:   "ipv4",
				Scope:   "link",
			},
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Route: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Address", "Address") != "192.168.1.15/24" {
		t.Fatalf("Failed to set Address")
	}
	if m.GetKeySectionString("Address", "Peer") != "192.168.10.10/24" {
		t.Fatalf("Failed to set Peer")
	}
	if m.GetKeySectionString("Address", "Label") != "ipv4" {
		t.Fatalf("Failed to set Label")
	}
	if m.GetKeySectionString("Address", "Scope") != "link" {
		t.Fatalf("Failed to set Scope")
	}
}

func TestNetworkLinkMode(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		LinkSection: networkd.LinkSection{
			ARP:               "yes",
			Multicast:         "yes",
			AllMulticast:      "no",
			Promiscuous:       "no",
			RequiredForOnline: "yes",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Link Mode: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Link", "ARP") != "yes" {
		t.Fatalf("Failed to set ARP")
	}
	if m.GetKeySectionString("Link", "Multicast") != "yes" {
		t.Fatalf("Failed to set Multicast")
	}
	if m.GetKeySectionString("Link", "AllMulticast") != "no" {
		t.Fatalf("Failed to set AllMulticast")
	}
	if m.GetKeySectionString("Link", "Promiscuous") != "no" {
		t.Fatalf("Failed to set Promiscuous")
	}
	if m.GetKeySectionString("Link", "RequiredForOnline") != "yes" {
		t.Fatalf("Failed to set RequiredForOnline")
	}
}

func TestNetworkLinkMTU(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		LinkSection: networkd.LinkSection{
			MTUBytes: "2048",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Link MTU: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Link", "MTUBytes") != "2048" {
		t.Fatalf("Failed to set MTUBytes")
	}
}

func TestNetworkLinkMAC(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		LinkSection: networkd.LinkSection{
			MACAddress: "00:a0:de:63:7a:e6",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Link MAC: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Link", "MACAddress") != "00:a0:de:63:7a:e6" {
		t.Fatalf("Failed to set MACAddress")
	}
}

func TestNetworkLinkGroup(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		LinkSection: networkd.LinkSection{
			Group: "2147483647",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Link Group: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Link", "Group") != "2147483647" {
		t.Fatalf("Failed to set Group")
	}
}

func TestNetworkLinkOnlineFamily(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		LinkSection: networkd.LinkSection{
			RequiredFamilyForOnline: "ipv4",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Link OnlineFamily: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Link", "RequiredFamilyForOnline") != "ipv4" {
		t.Fatalf("Failed to set RequiredFamilyForOnline")
	}
}

func TestNetworkLinkActPolicy(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		LinkSection: networkd.LinkSection{
			ActivationPolicy: "always-up",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure Link ActPolicy: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Link", "ActivationPolicy") != "always-up" {
		t.Fatalf("Failed to set ActivationPolicy")
	}
}

func TestNetworkAddRoutingPolicyRule(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		RoutingPolicyRuleSections: []networkd.RoutingPolicyRuleSection{
			{
				TypeOfService:          "12",
				From:                   "192.168.1.10/24",
				To:                     "192.168.2.20/24",
				FirewallMark:           "7/255",
				Table:                  "8",
				Priority:               "2",
				IncomingInterface:      "test99",
				OutgoingInterface:      "test99",
				SourcePort:             "8000-8080",
				DestinationPort:        "9876",
				IPProtocol:             "tcp",
				InvertRule:             "yes",
				Family:                 "both",
				User:                   "1010-1020",
				SuppressPrefixLength:   "128",
				SuppressInterfaceGroup: "204",
				Type:                   "prohibit",
			},
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure RoutingPolicyRule: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("RoutingPolicyRule", "TypeOfService") != "12" {
		t.Fatalf("Failed to set TypeOfService")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "From") != "192.168.1.10/24" {
		t.Fatalf("Failed to set From")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "To") != "192.168.2.20/24" {
		t.Fatalf("Failed to set To")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "FirewallMark") != "7/255" {
		t.Fatalf("Failed to set FirewallMark")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "Table") != "8" {
		t.Fatalf("Failed to set Table")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "Priority") != "2" {
		t.Fatalf("Failed to set Priority")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "IncomingInterface") != "test99" {
		t.Fatalf("Failed to set IncomingInterface")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "OutgoingInterface") != "test99" {
		t.Fatalf("Failed to set OutgoingInterface")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "SourcePort") != "8000-8080" {
		t.Fatalf("Failed to set SourcePort")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "DestinationPort") != "9876" {
		t.Fatalf("Failed to set DestinationPort")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "IPProtocol") != "tcp" {
		t.Fatalf("Failed to set IPProtocol")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "InvertRule") != "yes" {
		t.Fatalf("Failed to set InvertRule")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "Family") != "both" {
		t.Fatalf("Failed to set Family")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "User") != "1010-1020" {
		t.Fatalf("Failed to set User")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "SuppressPrefixLength") != "128" {
		t.Fatalf("Failed to set SuppressPrefixLength")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "SuppressInterfaceGroup") != "204" {
		t.Fatalf("Failed to set SuppressInterfaceGroup")
	}
	if m.GetKeySectionString("RoutingPolicyRule", "Type") != "prohibit" {
		t.Fatalf("Failed to set Type")
	}
}

func TestNetworkRemoveRoutingPolicyRule(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		RoutingPolicyRuleSections: []networkd.RoutingPolicyRuleSection{
			{
				TypeOfService:     "12",
				From:              "192.168.1.10/24",
				To:                "192.168.2.20/24",
				Table:             "8",
				Priority:          "2",
				IncomingInterface: "test99",
				OutgoingInterface: "test99",
			},
		},
	}

	_, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure RoutingPolicyRule: %v\n", err)
	}

	n = networkd.Network{
		Link: "test99",
		RoutingPolicyRuleSections: []networkd.RoutingPolicyRuleSection{
			{
				TypeOfService: "12",
			},
		},
	}

	m, err := removeNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to remove RoutingPolicyRule: %v\n", err)
	}

	if m.GetKeySectionString("RoutingPolicyRule", "TypeOfService") == "12" ||
		m.GetKeySectionString("RoutingPolicyRule", "From") == "192.168.1.10/24" ||
		m.GetKeySectionString("RoutingPolicyRule", "To") == "192.168.2.20/24" ||
		m.GetKeySectionString("RoutingPolicyRule", "Table") == "8" ||
		m.GetKeySectionString("RoutingPolicyRule", "Priority") == "2" ||
		m.GetKeySectionString("RoutingPolicyRule", "IncomingInterface") == "test99" ||
		m.GetKeySectionString("RoutingPolicyRule", "OutgoingInterface") == "test99" {
		t.Fatalf("Failed to remove RoutingPolicyRule")
	}
}

func TestNetworkConfigureDHCPv4Id(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv4Section: networkd.DHCPv4Section{
			ClientIdentifier:      "duid",
			VendorClassIdentifier: "101",
			IAID:                  "201",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv4 Identifier: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv4", "ClientIdentifier") != "duid" {
		t.Fatalf("Failed to set ClientIdentifier")
	}
	if m.GetKeySectionString("DHCPv4", "VendorClassIdentifier") != "101" {
		t.Fatalf("Failed to set VendorClassIdentifier")
	}
	if m.GetKeySectionString("DHCPv4", "IAID") != "201" {
		t.Fatalf("Failed to set IAID")
	}
}

func TestNetworkConfigureDHCPv4DUID(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv4Section: networkd.DHCPv4Section{
			DUIDType:    "vendor",
			DUIDRawData: "af:03:ff:87",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv4 duid: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv4", "DUIDType") != "vendor" {
		t.Fatalf("Failed to set DUIDType")
	}
	if m.GetKeySectionString("DHCPv4", "DUIDRawData") != "af:03:ff:87" {
		t.Fatalf("Failed to set DUIDrawData")
	}
}

func TestNetworkConfigureDHCPv4UseOption(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv4Section: networkd.DHCPv4Section{
			UseDNS:      "no",
			UseNTP:      "no",
			UseSIP:      "no",
			UseMTU:      "yes",
			UseHostname: "yes",
			UseDomains:  "yes",
			UseRoutes:   "no",
			UseGateway:  "yes",
			UseTimezone: "no",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv4 Use: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv4", "UseDNS") != "no" {
		t.Fatalf("Failed to set UseDNS")
	}
	if m.GetKeySectionString("DHCPv4", "UseNTP") != "no" {
		t.Fatalf("Failed to set UseNTP")
	}
	if m.GetKeySectionString("DHCPv4", "UseSIP") != "no" {
		t.Fatalf("Failed to set UseSIP")
	}
	if m.GetKeySectionString("DHCPv4", "UseMTU") != "yes" {
		t.Fatalf("Failed to set UseMTU")
	}
	if m.GetKeySectionString("DHCPv4", "UseHostname") != "yes" {
		t.Fatalf("Failed to set UseHostname")
	}
	if m.GetKeySectionString("DHCPv4", "UseDomains") != "yes" {
		t.Fatalf("Failed to set UseDomains")
	}
	if m.GetKeySectionString("DHCPv4", "UseRoutes") != "no" {
		t.Fatalf("Failed to set UseRoutes")
	}
	if m.GetKeySectionString("DHCPv4", "UseGateway") != "yes" {
		t.Fatalf("Failed to set UseGateway")
	}
	if m.GetKeySectionString("DHCPv4", "UseTimezone") != "no" {
		t.Fatalf("Failed to set UseTimezone")
	}
}

func TestNetworkConfigureAddDHCPv4Server(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			DHCPServer: "yes",
		},
		DHCPv4ServerSection: networkd.DHCPv4ServerSection{
			PoolOffset:          "100",
			PoolSize:            "200",
			DefaultLeaseTimeSec: "10",
			MaxLeaseTimeSec:     "30",
			DNS:                 []string{"192.168.1.2", "192.168.10.10", "192.168.20.30"},
			EmitDNS:             "yes",
			EmitNTP:             "no",
			EmitRouter:          "yes",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPServer: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "DHCPServer") != "yes" {
		t.Fatalf("Failed to set DHCPServer")
	}
	if m.GetKeySectionString("DHCPServer", "PoolOffset") != "100" {
		t.Fatalf("Failed to set PoolOffset")
	}
	if m.GetKeySectionString("DHCPServer", "PoolSize") != "200" {
		t.Fatalf("Failed to set PoolSize")
	}
	if m.GetKeySectionString("DHCPServer", "DefaultLeaseTimeSec") != "10" {
		t.Fatalf("Failed to set DefaultLeaseTimeSec")
	}
	if m.GetKeySectionString("DHCPServer", "MaxLeaseTimeSec") != "30" {
		t.Fatalf("Failed to set MaxLeaseTimeSec")
	}
	if m.GetKeySectionString("DHCPServer", "DNS") != "192.168.1.2 192.168.10.10 192.168.20.30" {
		t.Fatalf("Failed to set DNS")
	}
	if m.GetKeySectionString("DHCPServer", "EmitDNS") != "yes" {
		t.Fatalf("Failed to set EmitDNS")
	}
	if m.GetKeySectionString("DHCPServer", "EmitNTP") != "no" {
		t.Fatalf("Failed to set EmitNTP")
	}
	if m.GetKeySectionString("DHCPServer", "EmitRouter") != "yes" {
		t.Fatalf("Failed to set EmitRouter")
	}
}

func TestNetworkConfigureRemoveDHCPv4Server(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			DHCPServer: "yes",
		},
		DHCPv4ServerSection: networkd.DHCPv4ServerSection{
			PoolOffset:          "100",
			PoolSize:            "200",
			DefaultLeaseTimeSec: "10",
			MaxLeaseTimeSec:     "30",
			DNS:                 []string{"192.168.1.2", "192.168.10.10", "192.168.20.30"},
			EmitDNS:             "yes",
			EmitNTP:             "no",
			EmitRouter:          "yes",
		},
	}

	_, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPServer: %v\n", err)
	}

	n = networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			DHCPServer: "no",
		},
	}

	m, err := removeNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to remove DHCPServer: %v\n", err)
	}

	if m.GetKeySectionString("Network", "DHCPServer") == "yes" ||
		m.GetKeySectionString("DHCPServer", "PoolOffset") == "100" ||
		m.GetKeySectionString("DHCPServer", "PoolSize") == "200" ||
		m.GetKeySectionString("DHCPServer", "DefaultLeaseTimeSec") == "10" ||
		m.GetKeySectionString("DHCPServer", "MaxLeaseTimeSec") == "30" ||
		m.GetKeySectionString("DHCPServer", "DNS") == "192.168.1.2 192.168.10.10 192.168.20.30" ||
		m.GetKeySectionString("DHCPServer", "EmitDNS") == "yes" ||
		m.GetKeySectionString("DHCPServer", "EmitNTP") == "no" ||
		m.GetKeySectionString("DHCPServer", "EmitRouter") == "yes" {
		t.Fatalf("Failed to remove DHCPServer")
	}
}

func TestNetworkConfigureIPv6SendRA(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			IPv6SendRA: "yes",
		},
		IPv6SendRASection: networkd.IPv6SendRASection{
			RouterPreference: "medium",
			EmitDNS:          "yes",
			DNS:              []string{"2002:da8:1::1", "2002:da8:2::1"},
			EmitDomains:      "yes",
			Domains:          []string{"test1.com", "test2.com"},
			DNSLifetimeSec:   "100",
		},
		IPv6PrefixSections: []networkd.IPv6PrefixSection{
			{
				Prefix:               "2002:da8:1::/64",
				PreferredLifetimeSec: "100",
				ValidLifetimeSec:     "200",
				Assign:               "yes",
			},
		},
		IPv6RoutePrefixSections: []networkd.IPv6RoutePrefixSection{
			{
				Route:       "2001:db1:fff::/64",
				LifetimeSec: "1000",
			},
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure IPv6SendRA: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("Network", "IPv6SendRA") != "yes" {
		t.Fatalf("Failed to set IPv6SendRA")
	}
	if m.GetKeySectionString("IPv6SendRA", "RouterPreference") != "medium" {
		t.Fatalf("Failed to set RouterPreference")
	}
	if m.GetKeySectionString("IPv6SendRA", "EmitDNS") != "yes" {
		t.Fatalf("Failed to set EmitDNS")
	}
	if m.GetKeySectionString("IPv6SendRA", "DNS") != "2002:da8:1::1 2002:da8:2::1" {
		t.Fatalf("Failed to set DNS")
	}
	if m.GetKeySectionString("IPv6SendRA", "EmitDomains") != "yes" {
		t.Fatalf("Failed to set EmitDomains")
	}
	if m.GetKeySectionString("IPv6SendRA", "Domains") != "test1.com test2.com" {
		t.Fatalf("Failed to set Domains")
	}
	if m.GetKeySectionString("IPv6SendRA", "DNSLifetimeSec") != "100" {
		t.Fatalf("Failed to set DNSLifetimeSec")
	}
	if m.GetKeySectionString("IPv6Prefix", "Prefix") != "2002:da8:1::/64" {
		t.Fatalf("Failed to set Prefix")
	}
	if m.GetKeySectionString("IPv6Prefix", "PreferredLifetimeSec") != "100" {
		t.Fatalf("Failed to set PreferredLifetimeSec")
	}
	if m.GetKeySectionString("IPv6Prefix", "ValidLifetimeSec") != "200" {
		t.Fatalf("Failed to set ValidLifetimeSec")
	}
	if m.GetKeySectionString("IPv6Prefix", "Assign") != "yes" {
		t.Fatalf("Failed to set Assign")
	}
	if m.GetKeySectionString("IPv6RoutePrefix", "Route") != "2001:db1:fff::/64" {
		t.Fatalf("Failed to set Route")
	}
	if m.GetKeySectionString("IPv6RoutePrefix", "LifetimeSec") != "1000" {
		t.Fatalf("Failed to set LifetimeSec")
	}
}

func TestNetworkRemoveIPv6SendRA(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			IPv6SendRA: "yes",
		},
		IPv6SendRASection: networkd.IPv6SendRASection{
			RouterPreference: "medium",
			EmitDNS:          "yes",
			DNS:              []string{"2002:da8:1::1", "2002:da8:2::1"},
			EmitDomains:      "yes",
			Domains:          []string{"test1.com", "test2.com"},
			DNSLifetimeSec:   "100",
		},
		IPv6PrefixSections: []networkd.IPv6PrefixSection{
			{
				Prefix:               "2002:da8:1::/64",
				PreferredLifetimeSec: "100",
				ValidLifetimeSec:     "200",
				Assign:               "yes",
			},
		},
		IPv6RoutePrefixSections: []networkd.IPv6RoutePrefixSection{
			{
				Route:       "2001:db1:fff::/64",
				LifetimeSec: "1000",
			},
		},
	}

	_, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure IPv6SendRA: %v\n", err)
	}

	n = networkd.Network{
		Link: "test99",
		NetworkSection: networkd.NetworkSection{
			IPv6SendRA: "no",
		},
	}

	m, err := removeNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to remove IPv6SendRA: %v\n", err)
	}

	if m.GetKeySectionString("Network", "IPv6SendRA") == "yes" ||
		m.GetKeySectionString("IPv6SendRA", "RouterPreference") == "medium" ||
		m.GetKeySectionString("IPv6SendRA", "EmitDNS") == "yes" ||
		m.GetKeySectionString("IPv6SendRA", "DNS") == "2002:da8:1::1 2002:da8:2::1" ||
		m.GetKeySectionString("IPv6SendRA", "EmitDomains") == "yes" ||
		m.GetKeySectionString("IPv6SendRA", "Domains") == "test1.com test2.com" ||
		m.GetKeySectionString("IPv6SendRA", "DNSLifetimeSec") == "100" ||
		m.GetKeySectionString("IPv6Prefix", "Prefix") == "2002:da8:1::/64" ||
		m.GetKeySectionString("IPv6Prefix", "PreferredLifetimeSec") == "100" ||
		m.GetKeySectionString("IPv6Prefix", "ValidLifetimeSec") == "200" ||
		m.GetKeySectionString("IPv6Prefix", "Assign") == "yes" ||
		m.GetKeySectionString("IPv6RoutePrefix", "Route") == "2001:db1:fff::/64" ||
		m.GetKeySectionString("IPv6RoutePrefix", "LifetimeSec") == "1000" {
		t.Fatalf("Failed to remove IPv6SendRA")
	}
}

func TestNetworkConfigureDHCPv6(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv6Section: networkd.DHCPv6Section{
			MUDURL:               "https://example.com/devB",
			UserClass:            []string{"usrcls1", "usrcls2"},
			VendorClass:          []string{"vdrcls1"},
			PrefixDelegationHint: "2001:db1:fff::/64",
			WithoutRA:            "solicit",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv6: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv6", "MUDURL") != "https://example.com/devB" {
		t.Fatalf("Failed to set MUDURL")
	}
	if m.GetKeySectionString("DHCPv6", "UserClass") != "usrcls1 usrcls2" {
		t.Fatalf("Failed to set UserClass")
	}
	if m.GetKeySectionString("DHCPv6", "VendorClass") != "vdrcls1" {
		t.Fatalf("Failed to set VendorClass")
	}
	if m.GetKeySectionString("DHCPv6", "PrefixDelegationHint") != "2001:db1:fff::/64" {
		t.Fatalf("Failed to set PrefixDelegationHint")
	}
	if m.GetKeySectionString("DHCPv6", "WithoutRA") != "solicit" {
		t.Fatalf("Failed to set WithoutRA")
	}
}

func TestNetworkConfigureDHCPv6Id(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv6Section: networkd.DHCPv6Section{
			IAID:        "8765434",
			DUIDType:    "vendor",
			DUIDRawData: "af:03:ff:87",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv6 Identifier: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv6", "IAID") != "8765434" {
		t.Fatalf("Failed to set IAID")
	}
	if m.GetKeySectionString("DHCPv6", "DUIDType") != "vendor" {
		t.Fatalf("Failed to set DUIDType")
	}
	if m.GetKeySectionString("DHCPv6", "DUIDRawData") != "af:03:ff:87" {
		t.Fatalf("Failed to set DUIDrawData")
	}
}

func TestNetworkConfigureDHCPv6Use(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv6Section: networkd.DHCPv6Section{
			UseAddress:         "yes",
			UseDelegatedPrefix: "no",
			UseDNS:             "no",
			UseNTP:             "no",
			UseHostname:        "yes",
			UseDomains:         "yes",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv6 Use: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv6", "UseAddress") != "yes" {
		t.Fatalf("Failed to set UseAddress")
	}
	if m.GetKeySectionString("DHCPv6", "UseDelegatedPrefix") != "no" {
		t.Fatalf("Failed to set UseDelegatedPrefix")
	}
	if m.GetKeySectionString("DHCPv6", "UseDNS") != "no" {
		t.Fatalf("Failed to set UseDNS")
	}
	if m.GetKeySectionString("DHCPv6", "UseNTP") != "no" {
		t.Fatalf("Failed to set UseNTP")
	}
	if m.GetKeySectionString("DHCPv6", "UseHostname") != "yes" {
		t.Fatalf("Failed to set UseHostname")
	}
	if m.GetKeySectionString("DHCPv6", "UseDomains") != "yes" {
		t.Fatalf("Failed to set UseDomains")
	}
}

func TestNetworkConfigureDHCPv6Option(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	n := networkd.Network{
		Link: "test99",
		DHCPv6Section: networkd.DHCPv6Section{
			RequestOptions:   []string{"10", "198", "34"},
			SendOption:       "34563",
			SendVendorOption: "1987653,65,ipv6address,af:03:ff:87",
		},
	}

	m, err := configureNetwork(t, n)
	if err != nil {
		t.Fatalf("Failed to configure DHCPv6 Use: %v\n", err)
	}
	defer os.Remove(m.Path)

	if m.GetKeySectionString("DHCPv6", "RequestOptions") != "10 198 34" {
		t.Fatalf("Failed to set RequestOptions")
	}
	if m.GetKeySectionString("DHCPv6", "SendOption") != "34563" {
		t.Fatalf("Failed to set SendOption")
	}
	if m.GetKeySectionString("DHCPv6", "SendVendorOption") != "1987653:65:ipv6address:af:03:ff:87" {
		t.Fatalf("Failed to set SendVendorOption")
	}
}
