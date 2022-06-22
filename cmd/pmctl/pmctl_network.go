// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/fatih/color"
	"github.com/pmd-nextgen/pkg/share"
	"github.com/pmd-nextgen/pkg/validator"
	"github.com/pmd-nextgen/pkg/web"
	"github.com/pmd-nextgen/plugins/network"
	"github.com/pmd-nextgen/plugins/network/netlink/address"
	"github.com/pmd-nextgen/plugins/network/netlink/link"
	"github.com/pmd-nextgen/plugins/network/netlink/route"
	"github.com/pmd-nextgen/plugins/network/networkd"
	"github.com/pmd-nextgen/plugins/network/resolved"
	"github.com/pmd-nextgen/plugins/network/timesyncd"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/urfave/cli/v2"
)

type NetDevIOCounters struct {
	Success bool                 `json:"success"`
	Message []net.IOCountersStat `json:"message"`
	Errors  string               `json:"errors"`
}

type Interface struct {
	Success bool                `json:"success"`
	Message []net.InterfaceStat `json:"message"`
	Errors  string              `json:"errors"`
}

type NetworkDescribe struct {
	Success bool             `json:"success"`
	Message network.Describe `json:"message"`
	Errors  string           `json:"errors"`
}

type ResolveDescribe struct {
	Success bool              `json:"success"`
	Message resolved.Describe `json:"message"`
	Errors  string            `json:"errors"`
}

func displayInterfaces(i *Interface) {
	for _, n := range i.Message {
		fmt.Printf("            %v %v\n", color.HiBlueString("Name:"), n.Name)
		fmt.Printf("           %v %v\n", color.HiBlueString("Index:"), n.Index)
		fmt.Printf("             %v %v\n", color.HiBlueString("MTU:"), n.MTU)

		fmt.Printf("           %v", color.HiBlueString("Flags:"))
		for _, j := range n.Flags {
			fmt.Printf(" %v", j)
		}
		fmt.Printf("\n")

		fmt.Printf("%v %v\n", color.HiBlueString("Hardware Address:"), n.HardwareAddr)

		fmt.Printf("       %v", color.HiBlueString("Addresses:"))
		for _, j := range n.Addrs {
			fmt.Printf(" %v", j.Addr)
		}
		fmt.Printf("\n\n")
	}
}

func displayNetDevIOStatistics(netDev *NetDevIOCounters) {
	for _, n := range netDev.Message {
		fmt.Printf("            %v %v\n", color.HiBlueString("Name:"), n.Name)
		fmt.Printf("%v %v\n", color.HiBlueString("Packets received:"), n.PacketsRecv)
		fmt.Printf("%v %v\n", color.HiBlueString("  Bytes received:"), n.PacketsSent)
		fmt.Printf("%v %v\n", color.HiBlueString("      Bytes sent:"), n.PacketsSent)
		fmt.Printf("%v %v\n", color.HiBlueString("         Drop in:"), n.PacketsSent)
		fmt.Printf("%v %v\n", color.HiBlueString("        Drop out:"), n.Dropin)
		fmt.Printf("%v %v\n", color.HiBlueString("        Error in:"), n.Dropout)
		fmt.Printf("%v %v\n", color.HiBlueString("       Error out:"), n.Errout)
		fmt.Printf("%v %v\n", color.HiBlueString("         Fifo in:"), n.Fifoin)
		fmt.Printf("%v %v\n\n", color.HiBlueString("        Fifo out:"), n.Fifoout)
	}
}

func displayOneLinkNetworkStatus(l *networkd.LinkDescribe) {
	fmt.Printf("             %v %v\n", color.HiBlueString("Name:"), l.Name)
	if len(l.AlternativeNames) > 0 {
		fmt.Printf("%v %v\n", color.HiBlueString("Alternative Names:"), strings.Join(l.AlternativeNames, " "))
	}
	fmt.Printf("            %v %v\n", color.HiBlueString("Index:"), l.Index)
	if l.LinkFile != "" {
		fmt.Printf("        %v %v\n", color.HiBlueString("Link File:"), l.LinkFile)
	}
	if l.NetworkFile != "" {
		fmt.Printf("     %v %v\n", color.HiBlueString("Network File:"), l.NetworkFile)
	}
	fmt.Printf("             %v %v\n", color.HiBlueString("Type:"), l.Type)
	fmt.Printf("            %v %v (%v)\n", color.HiBlueString("State:"), l.OperationalState, l.SetupState)
	if l.Driver != "" {
		fmt.Printf("           %v %v\n", color.HiBlueString("Driver:"), l.Driver)
	}
	if l.Vendor != "" {
		fmt.Printf("           %v %v\n", color.HiBlueString("Vendor:"), l.Vendor)
	}
	if l.Model != "" {
		fmt.Printf("            %v %v\n", color.HiBlueString("Model:"), l.Model)
	}
	if l.Path != "" {
		fmt.Printf("             %v %v\n", color.HiBlueString("Path:"), l.Path)
	}
	fmt.Printf("    %v %v\n", color.HiBlueString("Carrier State:"), l.CarrierState)

	if l.OnlineState != "" {
		fmt.Printf("     %v %v\n", color.HiBlueString("Online State:"), l.OnlineState)
	}
	if l.IPv4AddressState != "" {
		fmt.Printf("%v %v\n", color.HiBlueString("IPv4Address State:"), l.IPv4AddressState)
	}
	if l.IPv6AddressState != "" {
		fmt.Printf("%v %v\n", color.HiBlueString("IPv6Address State:"), l.IPv6AddressState)
	}
}

func displayOneLink(l *link.LinkInfo) {
	if l.HardwareAddr != "" {
		fmt.Printf("       %v %v\n", color.HiBlueString("HW Address:"), l.HardwareAddr)
	}
	fmt.Printf("              %v %v\n", color.HiBlueString("MTU:"), l.Mtu)
	fmt.Printf("        %v %v\n", color.HiBlueString("OperState:"), l.OperState)
	fmt.Printf("            %v %v\n", color.HiBlueString("Flags:"), l.Flags)
}

func displayOneLinkAddresses(addInfo *address.AddressInfo) {
	fmt.Printf("        %v", color.HiBlueString("Addresses:"))
	for _, a := range addInfo.Addresses {
		fmt.Printf(" %v/%v", a.IP, a.Mask)
	}
	fmt.Printf("\n")
}

func displayOneLinkRoutes(ifIndex int, linkRoutes []route.RouteInfo) {
	gws := share.NewSet()
	for _, rt := range linkRoutes {
		if rt.LinkIndex == ifIndex && rt.Gw != "" {
			gws.Add(rt.Gw)
		}
	}

	if gws.Length() > 0 {
		fmt.Printf("          %v %v\n", color.HiBlueString("Gateway:"), strings.Join(gws.Values(), " "))
	}
}

func displayOneLinkDnsAndDomains(link string, dns []resolved.Dns, domains []resolved.Domains) {
	dnsServers := share.NewSet()
	for _, d := range dns {
		if d.Link == link {
			dnsServers.Add(d.Dns)
		}
	}

	if dnsServers.Length() > 0 {
		fmt.Printf("              %v %v\n", color.HiBlueString("DNS:"), strings.Join(dnsServers.Values(), " "))
	}

	domain := share.NewSet()
	for _, d := range domains {
		if d.Link == link {
			domain.Add(d.Domain)
		}
	}

	if domain.Length() > 0 {
		fmt.Printf("           %v %v\n", color.HiBlueString("Domains:"), strings.Join(dnsServers.Values(), " "))
	}
}

func displayDnsAndDomains(n *resolved.Describe) {
	fmt.Printf("%v\n\n", color.HiBlueString("Global"))
	if !validator.IsEmpty(n.CurrentDNS) {
		fmt.Printf("%v %v\n", color.HiBlueString("CurrentDNS: "), n.CurrentDNS)
	}

	fmt.Printf("%v", color.HiBlueString("        DNS: "))
	for _, d := range n.DnsServers {
		if validator.IsEmpty(d.Link) {
			fmt.Printf("%v ", d.Dns)
		}
	}
	fmt.Printf("\n%v", color.HiBlueString("DNS Domains: "))
	for _, d := range n.Domains {
		fmt.Printf("%v ", d.Domain)
	}

	type linkDns struct {
		Index int32
		Link  string
		Dns   []string
	}

	l := linkDns{}
	dns := make(map[int32]*linkDns)
	for _, d := range n.DnsServers {
		if !validator.IsEmpty(d.Link) {
			if dns[d.Index] != nil {
				l := dns[d.Index]
				l.Dns = append(l.Dns, d.Dns)
			} else {
				dns[d.Index] = &linkDns{
					Index: d.Index,
					Link:  d.Link,
					Dns:   append(l.Dns, d.Dns),
				}
			}
		}
	}

	for _, d := range dns {
		fmt.Printf("\n%v %v (%v)\n", color.HiBlueString("Link"), d.Index, d.Link)
		for _, c := range n.LinkCurrentDNS {
			if c.Index == d.Index {
				fmt.Printf("%v %v\n", color.HiBlueString("Current DNS Server: "), c.Dns)
			}
		}
		fmt.Printf("       %v %v\n", color.HiBlueString("DNS Servers: "), strings.Join(d.Dns, " "))
	}
}

func displayOneLinkNTP(link string, ntp *timesyncd.Describe) {
	if len(ntp.LinkNTPServers) > 0 {
		fmt.Printf("              %v %v\n", color.HiBlueString("NTP:"), ntp.LinkNTPServers)
	}
}

func displayNetworkStatus(ifName string, network *network.Describe) {
	for _, link := range network.Links {
		if ifName != "" && link.Name != ifName {
			continue
		}

		for _, l := range network.LinksDescribe.Interfaces {
			if link.Name == l.Name {
				displayOneLinkNetworkStatus(&l)
			}
		}

		displayOneLink(&link)

		for _, l := range network.Addresses {
			if l.Name == link.Name {
				displayOneLinkAddresses(&l)
			}
		}

		displayOneLinkRoutes(link.Index, network.Routes)

		if link.Name != "lo" {
			if len(network.Dns) > 0 {
				displayOneLinkDnsAndDomains(link.Name, network.Dns, network.Domains)
			}
		}

		fmt.Printf("\n")
	}
}

func acquireNetworkDescribe(host string, token map[string]string) (*network.Describe, error) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/network/describe", token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire network info: %v\n", err)
		return nil, err
	}

	n := NetworkDescribe{}
	if err := json.Unmarshal(resp, &n); err != nil {
		fmt.Printf("Failed to decode link json message: %v\n", err)
		return nil, err
	}

	if n.Success {
		return &n.Message, nil
	}

	return nil, errors.New(n.Errors)
}

func acquireResolveDescribe(host string, token map[string]string) error {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/network/resolved/describe", token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire resolve info: %v\n", err)
		return err
	}

	n := ResolveDescribe{}
	if err := json.Unmarshal(resp, &n); err != nil {
		fmt.Printf("Failed to decode link json message: %v\n", err)
		return err
	}

	if n.Success {
		displayDnsAndDomains(&n.Message)
	}

	return nil
}

func acquireNetworkStatus(cmd string, host string, ifName string, token map[string]string) {
	switch cmd {
	case "network":
		n, err := acquireNetworkDescribe(host, token)
		if err != nil {
			fmt.Printf("Failed to fetch network status: %v\n", err)
			return
		}

		displayNetworkStatus(ifName, n)

	case "iostat":
		resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/netdeviocounters", token, nil)
		if err != nil {
			fmt.Printf("Failed to fetch networks device's iostat: %v\n", err)
			return
		}

		n := NetDevIOCounters{}
		if err := json.Unmarshal(resp, &n); err != nil {
			fmt.Printf("Failed to decode json message: %v\n", err)
			return
		}

		if n.Success {
			displayNetDevIOStatistics(&n)
		}
	case "interfaces":
		resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/proc/interfaces", token, nil)
		if err != nil {
			fmt.Printf("Failed to fetch networks devices: %v\n", err)
			return
		}

		n := Interface{}
		if err := json.Unmarshal(resp, &n); err != nil {
			fmt.Printf("Failed to decode json message: %v\n", err)
			return
		}

		if n.Success {
			displayInterfaces(&n)
		}
	}
}

func networkConfigure(network *networkd.Network, host string, token map[string]string) {
	var resp []byte
	var err error

	resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/networkd/network/configure", token, *network)
	if err != nil {
		fmt.Printf("Failed to configure network: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to configure network: %v\n", m.Errors)
	}
}

func networkConfigureDHCP(link string, dhcp string, host string, token map[string]string) {
	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			DHCP: dhcp,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureLinkLocalAddressing(link string, linkLocalAddr string, host string, token map[string]string) {
	if !validator.IsLinkLocalAddressing(linkLocalAddr) {
		fmt.Printf("Invalid LinkLocalAddressing: %s\n", linkLocalAddr)
		return
	}

	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			LinkLocalAddressing: linkLocalAddr,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureMulticastDNS(link string, mcastDns string, host string, token map[string]string) {
	if !validator.IsMulticastDNS(mcastDns) {
		fmt.Printf("Invalid MulticastDNS: %s\n", mcastDns)
		return
	}

	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			MulticastDNS: mcastDns,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureRoute(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()
	link := ""

	r := networkd.RouteSection{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			link = argStrings[i+1]
		case "gw":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Failed to parse gw='%s'\n", argStrings[i+1])
				return
			}
			r.Gateway = argStrings[i+1]
		case "gwonlink":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to parse gwonlink='%s'\n", argStrings[i+1])
				return
			}
			r.GatewayOnlink = argStrings[i+1]
		case "dest":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Failed to parse dest='%s'\n", argStrings[i+1])
				return
			}
			r.Destination = argStrings[i+1]
		case "src":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Failed to parse src='%s'\n", argStrings[i+1])
				return
			}
			r.Source = argStrings[i+1]
		case "prefsrc":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Failed to parse prefsrc='%s'\n", argStrings[i+1])
				return
			}
			r.PreferredSource = argStrings[i+1]
		case "table":
			if !govalidator.IsInt(argStrings[i+1]) {
				fmt.Printf("Failed to parse table='%s'\n", argStrings[i+1])
				return
			}
			r.Table = argStrings[i+1]
		case "scope":
			if !validator.IsScope(argStrings[i+1]) {
				fmt.Printf("Failed to parse scope='%s'\n", argStrings[i+1])
				return
			}
			r.Scope = argStrings[i+1]
		}
	}

	n := networkd.Network{
		Link: link,
		RouteSections: []networkd.RouteSection{
			r,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureDHCPv4Id(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "clientid":
			if !validator.IsDHCPv4ClientIdentifier(argStrings[i+1]) {
				fmt.Printf("Invalid clientid=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.ClientIdentifier = argStrings[i+1]
		case "vendorclassid":
			if validator.IsEmpty(argStrings[i+1]) {
				fmt.Printf("Invalid vendorclassid=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.VendorClassIdentifier = argStrings[i+1]
		case "iaid":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid iaid=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.IAID = argStrings[i+1]
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureDHCPv4DUID(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "duidtype":
			if !validator.IsDHCPDUIDType(argStrings[i+1]) {
				fmt.Printf("Invalid duidtype=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.DUIDType = argStrings[i+1]
		case "duidrawdata":
			if validator.IsEmpty(argStrings[i+1]) {
				fmt.Printf("Invduidrawdata=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.DUIDRawData = argStrings[i+1]
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureDHCPv4UseOption(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "usedns":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usedns=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseDNS = validator.BoolToString(argStrings[i+1])
		case "usentp":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usentp=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseNTP = validator.BoolToString(argStrings[i+1])
		case "usesip":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usesip=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseSIP = validator.BoolToString(argStrings[i+1])
		case "usemtu":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usemtu=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseMTU = validator.BoolToString(argStrings[i+1])
		case "usehostname":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usehostname=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseHostname = validator.BoolToString(argStrings[i+1])
		case "usedomains":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usedomains=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseDomains = validator.BoolToString(argStrings[i+1])
		case "useroutes":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid useroutes=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseRoutes = validator.BoolToString(argStrings[i+1])
		case "usegateway":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usegateway=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseGateway = validator.BoolToString(argStrings[i+1])
		case "usetimezone":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usetimezone=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4Section.UseTimezone = validator.BoolToString(argStrings[i+1])
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureAddDHCPv4Server(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "pool-offset":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid pool-offset=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.PoolOffset = argStrings[i+1]
		case "pool-size":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid pool-size=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.PoolSize = argStrings[i+1]
		case "default-lease-time-sec":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid default-lease-time-sec=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.DefaultLeaseTimeSec = argStrings[i+1]
		case "max-lease-time-sec":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid max-lease-time-sec=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.MaxLeaseTimeSec = argStrings[i+1]
		case "dns":
			dnslist := strings.Split(argStrings[i+1], ",")
			for _, dns := range dnslist {
				if !validator.IsIP(dns) {
					fmt.Printf("Invalid dns=%s\n", dns)
					return
				}
			}
			n.DHCPv4ServerSection.DNS = dnslist
		case "emit-dns":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid emit-dns=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.EmitDNS = validator.BoolToString(argStrings[i+1])
		case "emit-ntp":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid emit-ntp=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.EmitNTP = validator.BoolToString(argStrings[i+1])
		case "emit-router":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid emit-router=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv4ServerSection.EmitRouter = validator.BoolToString(argStrings[i+1])
		}
	}

	n.NetworkSection.DHCPServer = "yes"
	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureRemoveDHCPv4Server(link string, host string, token map[string]string) {
	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			DHCPServer: "no",
		},
	}

	var resp []byte

	resp, err := web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/networkd/network/remove", token, n)
	if err != nil {
		fmt.Printf("Failed to remove network dhcp server: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove network dhcp server: %v\n", m.Errors)
	}
}

func networkConfigureMTU(link string, mtu string, host string, token map[string]string) {
	n := networkd.Network{
		Link: link,
		LinkSection: networkd.LinkSection{
			MTUBytes: mtu,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureMAC(link string, mac string, host string, token map[string]string) {
	n := networkd.Network{
		Link: link,
		LinkSection: networkd.LinkSection{
			MACAddress: mac,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureLinkGroup(link string, group string, host string, token map[string]string) {
	if !validator.IsEmpty(group) {
		if !validator.IsLinkGroup(group) {
			fmt.Printf("Failed to parse group: Invalid Group=%s\n", group)
			return
		}
	}

	n := networkd.Network{
		Link: link,
		LinkSection: networkd.LinkSection{
			Group: group,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureLinkRequiredFamilyForOnline(link string, rfonline string, host string, token map[string]string) {
	if !validator.IsEmpty(rfonline) {
		if !validator.IsAddressFamily(rfonline) {
			fmt.Printf("Failed to parse online family='%s'\n", rfonline)
			return
		}
	}

	n := networkd.Network{
		Link: link,
		LinkSection: networkd.LinkSection{
			RequiredFamilyForOnline: rfonline,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureLinkActivationPolicy(link string, policy string, host string, token map[string]string) {
	if !validator.IsEmpty(policy) {
		if !validator.IsLinkActivationPolicy(policy) {
			fmt.Printf("Failed to parse activation policy='%s'\n", policy)
			return
		}
	}

	n := networkd.Network{
		Link: link,
		LinkSection: networkd.LinkSection{
			ActivationPolicy: policy,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureMode(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "arp":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to parse arp='%s'\n", argStrings[i+1])
				return
			}
			n.LinkSection.ARP = validator.BoolToString(argStrings[i+1])
		case "mc":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to parse mc='%s'\n", argStrings[i+1])
				return
			}
			n.LinkSection.Multicast = validator.BoolToString(argStrings[i+1])
		case "amc":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to parse amc='%s'\n", argStrings[i+1])
				return
			}
			n.LinkSection.AllMulticast = validator.BoolToString(argStrings[i+1])
		case "pcs":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to parse pcs='%s'\n", argStrings[i+1])
				return
			}
			n.LinkSection.Promiscuous = validator.BoolToString(argStrings[i+1])
		case "rfo":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to parse rfo='%s'\n", argStrings[i+1])
				return
			}
			n.LinkSection.RequiredForOnline = validator.BoolToString(argStrings[i+1])
		}
	}

	networkConfigure(&n, host, token)
}

func networkConfigureAddress(link string, args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	a := networkd.AddressSection{}
	for i := 1; i < args.Len()-1; {
		switch argStrings[i] {
		case "address":
			a.Address = argStrings[i+1]
			if !validator.IsIP(a.Address) {
				fmt.Printf("Invalid IP address: %v\n", a.Address)
				return
			}
		case "peer":
			a.Peer = argStrings[i+1]
			if !validator.IsIP(a.Peer) {
				fmt.Printf("Invalid Peer IP address: %v\n", a.Peer)
				return
			}
		case "label":
			a.Label = argStrings[i+1]
		case "scope":
			a.Scope = argStrings[i+1]
			if !validator.IsScope(a.Scope) {
				fmt.Printf("Invalid scope: %s", a.Scope)
				return
			}
		default:
		}
		i++
	}
	n := networkd.Network{
		Link: link,
		AddressSections: []networkd.AddressSection{
			a,
		},
	}
	networkConfigure(&n, host, token)
}

func parseRoutingPolicyRule(args cli.Args) (*networkd.Network, error) {
	argStrings := args.Slice()
	link := ""

	r := networkd.RoutingPolicyRuleSection{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			link = argStrings[i+1]
		case "tos":
			if !validator.IsRoutingTypeOfService(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid tos=%s\n", argStrings[i+1])
			}
			r.TypeOfService = argStrings[i+1]
		case "from":
			if !validator.IsIP(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid from=%s\n", argStrings[i+1])
			}
			r.From = argStrings[i+1]
		case "to":
			if !validator.IsIP(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid to=%s\n", argStrings[i+1])
			}
			r.To = argStrings[i+1]
		case "fwmark":
			if !validator.IsRoutingFirewallMark(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid fwmark=%s\n", argStrings[i+1])
			}
			r.FirewallMark = argStrings[i+1]
		case "table":
			if !validator.IsUint32(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid table=%s\n", argStrings[i+1])
			}
			r.Table = argStrings[i+1]
		case "prio":
			if !validator.IsUint32(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid prio=%s\n", argStrings[i+1])
			}
			r.Priority = argStrings[i+1]
		case "iif":
			if validator.IsEmpty(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid iif=%s\n", argStrings[i+1])
			}
			r.IncomingInterface = argStrings[i+1]
		case "oif":
			if validator.IsEmpty(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid oif=%s\n", argStrings[i+1])
			}
			r.OutgoingInterface = argStrings[i+1]
		case "srcport":
			if !validator.IsRoutingPort(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid srcport=%s\n", argStrings[i+1])
			}
			r.SourcePort = argStrings[i+1]
		case "destport":
			if !validator.IsRoutingPort(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid destport=%s\n", argStrings[i+1])
			}
			r.DestinationPort = argStrings[i+1]
		case "ipproto":
			if !validator.IsRoutingIPProtocol(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid ipproto=%s\n", argStrings[i+1])
			}
			r.IPProtocol = argStrings[i+1]
		case "invertrule":
			if !validator.IsBool(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid invertrule=%s\n", argStrings[i+1])
			}
			r.InvertRule = validator.BoolToString(argStrings[i+1])
		case "family":
			if !validator.IsAddressFamily(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid family=%s\n", argStrings[i+1])
			}
			r.Family = argStrings[i+1]
		case "usr":
			if !validator.IsRoutingUser(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid usr=%s\n", argStrings[i+1])
			}
			r.User = argStrings[i+1]
		case "suppressprefixlen":
			if !validator.IsRoutingSuppressPrefixLength(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid suppressprefixlen=%s\n", argStrings[i+1])
			}
			r.SuppressPrefixLength = argStrings[i+1]
		case "suppressifgrp":
			if !validator.IsUint32(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid suppressifgrp=%s\n", argStrings[i+1])
			}
			r.SuppressInterfaceGroup = argStrings[i+1]
		case "type":
			if !validator.IsRoutingType(argStrings[i+1]) {
				return nil, fmt.Errorf("Invalid type=%s\n", argStrings[i+1])
			}
			r.Type = argStrings[i+1]
		}
	}

	n := networkd.Network{
		Link: link,
		RoutingPolicyRuleSections: []networkd.RoutingPolicyRuleSection{
			r,
		},
	}

	return &n, nil

}

func networkAddRoutingPolicyRule(args cli.Args, host string, token map[string]string) {
	n, err := parseRoutingPolicyRule(args)
	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	networkConfigure(n, host, token)
}

func networkRemoveRoutingPolicyRule(args cli.Args, host string, token map[string]string) {
	n, err := parseRoutingPolicyRule(args)
	if err != nil {
		fmt.Printf("%v", err)
		return
	}

	var resp []byte

	resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/networkd/network/remove", token, n)
	if err != nil {
		fmt.Printf("Failed to remove network routing policy rule: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove network routing policy rule: %v\n", m.Errors)
	}

}

func networkAddDns(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	var dev string
	var dns []string
	for i, args := range argStrings {
		switch args {
		case "dev":
			dev = argStrings[i+1]
		case "dns":
			dns = strings.Split(argStrings[i+1], ",")
		}
	}

	if validator.IsArrayEmpty(dns) {
		fmt.Printf("Failed to add dns. Missing dns server\n")
		return
	}

	var resp []byte
	var err error
	if validator.IsEmpty(dev) {
		n := resolved.GlobalDns{
			DnsServers: dns,
		}
		resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/resolved/add", token, n)
		if err != nil {
			fmt.Printf("Failed to add global Dns server: %v\n", err)
			return
		}
	} else {
		n := networkd.Network{
			Link: dev,
			NetworkSection: networkd.NetworkSection{
				DNS: dns,
			},
		}
		resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/networkd/network/configure", token, n)
		if err != nil {
			fmt.Printf("Failed to add link Dns server: %v\n", err)
			return
		}
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to add Dns server: %v\n", m.Errors)
	}
}

func networkRemoveDns(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	var dev string
	var dns []string
	for i, args := range argStrings {
		switch args {
		case "dev":
			dev = argStrings[i+1]
		case "dns":
			dns = strings.Split(argStrings[i+1], ",")
		}
	}

	if validator.IsArrayEmpty(dns) {
		fmt.Printf("Failed to remove dns. Missing dns server\n")
		return
	}

	var resp []byte
	var err error
	if validator.IsEmpty(dev) {
		n := resolved.GlobalDns{
			DnsServers: dns,
		}
		resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/resolved/remove", token, n)
		if err != nil {
			fmt.Printf("Failed to remove global Dns server: %v\n", err)
			return
		}
	} else {
		n := networkd.Network{
			Link: dev,
			NetworkSection: networkd.NetworkSection{
				DNS: dns,
			},
		}

		resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/networkd/network/remove", token, n)
		if err != nil {
			fmt.Printf("Failed to remove link Dns server: %v\n", err)
			return
		}
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove Dns server: %v\n", m.Errors)
	}
}

func networkAddDomains(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	var dev string
	var domains []string
	for i, args := range argStrings {
		switch args {
		case "dev":
			dev = argStrings[i+1]
		case "domains":
			domains = strings.Split(argStrings[i+1], ",")
		}
	}

	if validator.IsArrayEmpty(domains) {
		fmt.Printf("Failed to add domains. Missing domains\n")
		return
	}

	var resp []byte
	var err error
	if validator.IsEmpty(dev) {
		n := resolved.GlobalDns{
			Domains: domains,
		}
		resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/resolved/add", token, n)
		if err != nil {
			fmt.Printf("Failed to add global domains: %v\n", err)
			return
		}
	} else {
		n := networkd.Network{
			Link: dev,
			NetworkSection: networkd.NetworkSection{
				Domains: domains,
			},
		}
		resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/networkd/network/configure", token, n)
		if err != nil {
			fmt.Printf("Failed to add link  domains: %v\n", err)
			return
		}
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to add domains: %v\n", m.Errors)
	}
}

func networkRemoveDomains(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	var dev string
	var domains []string
	for i, args := range argStrings {
		switch args {
		case "dev":
			dev = argStrings[i+1]
		case "domains":
			domains = strings.Split(argStrings[i+1], ",")
		}
	}

	if validator.IsArrayEmpty(domains) {
		fmt.Printf("Failed to remove domains. Missing domains server\n")
		return
	}

	var resp []byte
	var err error
	if validator.IsEmpty(dev) {
		n := resolved.GlobalDns{
			Domains: domains,
		}
		resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/resolved/remove", token, n)
		if err != nil {
			fmt.Printf("Failed to remove global Dns server: %v\n", err)
			return
		}
	} else {
		n := networkd.Network{
			Link: dev,
			NetworkSection: networkd.NetworkSection{
				Domains: domains,
			},
		}

		resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/networkd/network/remove", token, n)
		if err != nil {
			fmt.Printf("Failed to remove link domains: %v\n", err)
			return
		}
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove domains: %v\n", m.Errors)
	}
}

func networkAddNTP(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	var dev string
	var ntp []string
	for i := range argStrings {
		switch argStrings[i] {
		case "dev":
			dev = argStrings[i+1]
		case "ntp":
			ntp = strings.Split(argStrings[i+1], ",")
		}
		i++
	}

	var resp []byte
	var err error
	if validator.IsEmpty(dev) {
		n := timesyncd.NTP{
			NTPServers: ntp,
		}
		resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/timesyncd/add", token, n)
		if err != nil {
			fmt.Printf("Failed to add global NTP server: %v\n", err)
			return
		}
	} else {
		n := networkd.Network{
			Link: dev,
			NetworkSection: networkd.NetworkSection{
				NTP: ntp,
			},
		}
		resp, err = web.DispatchSocket(http.MethodPost, host, "/api/v1/network/networkd/network/configure", token, n)
		if err != nil {
			fmt.Printf("Failed to add link NTP server: %v\n", err)
			return
		}
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to add NTP server: %v\n", m.Errors)
	}
}

func networkRemoveNTP(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	var dev string
	var ntp []string
	for i := range argStrings {
		switch argStrings[i] {
		case "dev":
			dev = argStrings[i+1]
		case "ntp":
			ntp = strings.Split(argStrings[i+1], ",")
		}
		i++
	}

	var resp []byte
	var err error
	if validator.IsEmpty(dev) {
		n := timesyncd.NTP{
			NTPServers: ntp,
		}
		resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/timesyncd/remove", token, n)
		if err != nil {
			fmt.Printf("Failed to remove global NTP server: %v\n", err)
			return
		}
	} else {
		n := networkd.Network{
			Link: dev,
			NetworkSection: networkd.NetworkSection{
				NTP: ntp,
			},
		}
		resp, err = web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/networkd/network/remove", token, n)
		if err != nil {
			fmt.Printf("Failed to remove link NTP server: %v\n", err)
			return
		}
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove NTP server: %v\n", m.Errors)
	}
}

func networkConfigureIPv6AcceptRA(link string, ipv6ara string, host string, token map[string]string) {
	if !validator.IsBool(ipv6ara) {
		fmt.Printf("Invalid IPv6AcceptRA: %s\n", ipv6ara)
		return
	}

	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			IPv6AcceptRA: ipv6ara,
		},
	}

	networkConfigure(&n, host, token)
}

func networkConfigureIPv6SendRA(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	link := ""
	s := networkd.IPv6SendRASection{}
	p := networkd.IPv6PrefixSection{}
	r := networkd.IPv6RoutePrefixSection{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			link = argStrings[i+1]
		case "rt-pref":
			if !validator.IsRouterPreference(argStrings[i+1]) {
				fmt.Printf("Invalid rt-pref=%s\n", argStrings[i+1])
				return
			}
			s.RouterPreference = argStrings[i+1]
		case "emit-dns":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid emit-dns=%s\n", argStrings[i+1])
				return
			}
			s.EmitDNS = validator.BoolToString(argStrings[i+1])
		case "dns":
			dnslist := strings.Split(argStrings[i+1], ",")
			for _, d := range dnslist {
				if !validator.IsIP(d) {
					fmt.Printf("Invalid dns=%s\n", d)
					return
				}
			}
			s.DNS = dnslist
		case "emit-domains":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid emit-domains=%s\n", argStrings[i+1])
				return
			}
			s.EmitDomains = validator.BoolToString(argStrings[i+1])
		case "domains":
			domainslist := strings.Split(argStrings[i+1], ",")
			s.Domains = domainslist
		case "dns-lifetime-sec":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid dns-lifetime-sec=%s\n", argStrings[i+1])
				return
			}
			s.DNSLifetimeSec = argStrings[i+1]
		case "prefix":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Invalid prefix=%s\n", argStrings[i+1])
				return
			}
			p.Prefix = argStrings[i+1]
		case "pref-lifetime-sec":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid pref-lifetime-sec=%s\n", argStrings[i+1])
				return
			}
			p.PreferredLifetimeSec = argStrings[i+1]
		case "valid-lifetime-sec":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid valid-lifetime-sec=%s\n", argStrings[i+1])
				return
			}
			p.ValidLifetimeSec = argStrings[i+1]
		case "assign":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid assign=%s\n", argStrings[i+1])
				return
			}
			p.Assign = validator.BoolToString(argStrings[i+1])
		case "route":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Invalid route=%s\n", argStrings[i+1])
				return
			}
			r.Route = argStrings[i+1]
		case "lifetime-sec":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid lifetime-sec=%s\n", argStrings[i+1])
				return
			}
			r.LifetimeSec = argStrings[i+1]
		}
	}

	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			IPv6SendRA: "yes",
		},
		IPv6SendRASection: s,
		IPv6PrefixSections: []networkd.IPv6PrefixSection{
			p,
		},
		IPv6RoutePrefixSections: []networkd.IPv6RoutePrefixSection{
			r,
		},
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureRemoveIPv6SendRA(link string, host string, token map[string]string) {
	n := networkd.Network{
		Link: link,
		NetworkSection: networkd.NetworkSection{
			IPv6SendRA: "no",
		},
	}

	var resp []byte

	resp, err := web.DispatchSocket(http.MethodDelete, host, "/api/v1/network/networkd/network/remove", token, n)
	if err != nil {
		fmt.Printf("Failed to remove network IPv6SendRA: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to remove network IPv6SendRA: %v\n", m.Errors)
	}
}

func networkConfigureDHCPv6(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "mudurl":
			if validator.IsEmpty(argStrings[i+1]) {
				fmt.Printf("Invalid mudurl=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.MUDURL = argStrings[i+1]
		case "userclass":
			if validator.IsEmpty(argStrings[i+1]) {
				fmt.Printf("Invalid userclass=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UserClass = strings.Split(argStrings[i+1], ",")
		case "vendorclass":
			if validator.IsEmpty(argStrings[i+1]) {
				fmt.Printf("Invalid vendorclass=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.VendorClass = strings.Split(argStrings[i+1], ",")
		case "prefixhint":
			if !validator.IsIP(argStrings[i+1]) {
				fmt.Printf("Invalid prefixhint=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.PrefixDelegationHint = argStrings[i+1]
		case "withoutra":
			if !validator.IsDHCPv6WithoutRA(argStrings[i+1]) {
				fmt.Printf("Invalid withoutra=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.WithoutRA = argStrings[i+1]
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureDHCPv6Id(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "iaid":
			if !validator.IsUint32(argStrings[i+1]) {
				fmt.Printf("Invalid iaid=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.IAID = argStrings[i+1]
		case "duidtype":
			if !validator.IsDHCPDUIDType(argStrings[i+1]) {
				fmt.Printf("Invalid duidtype=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.DUIDType = argStrings[i+1]
		case "duidrawdata":
			if validator.IsEmpty(argStrings[i+1]) {
				fmt.Printf("Invduidrawdata=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.DUIDRawData = argStrings[i+1]
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureDHCPv6Use(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "useaddr":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid useaddr=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UseAddress = validator.BoolToString(argStrings[i+1])
		case "useprefix":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid useprefix=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UseDelegatedPrefix = validator.BoolToString(argStrings[i+1])
		case "usedns":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usedns=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UseDNS = validator.BoolToString(argStrings[i+1])
		case "usentp":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usentp=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UseNTP = validator.BoolToString(argStrings[i+1])
		case "usehostname":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usehostname=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UseHostname = validator.BoolToString(argStrings[i+1])
		case "usedomains":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Invalid usedomains=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.UseDomains = validator.BoolToString(argStrings[i+1])
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}

func networkConfigureDHCPv6Option(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	n := networkd.Network{}
	for i, args := range argStrings {
		switch args {
		case "dev":
			n.Link = argStrings[i+1]
		case "reqopt":
			req := strings.Split(argStrings[i+1], ",")
			for _, r := range req {
				if !validator.IsUint8(r) {
					fmt.Printf("invalid reqopt=%s\n", r)
					return
				}
			}
			n.DHCPv6Section.RequestOptions = req
		case "sendopt":
			if !validator.IsUint16(argStrings[i+1]) {
				fmt.Printf("Invalid sendopt=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.SendOption = argStrings[i+1]
		case "sendvendoropt":
			if !validator.IsDHCPv6SendVendorOption(argStrings[i+1]) {
				fmt.Printf("Invalid sendvendoropt=%s\n", argStrings[i+1])
				return
			}
			n.DHCPv6Section.SendVendorOption = argStrings[i+1]
		}
	}

	// Dispatch Request.
	networkConfigure(&n, host, token)
}
