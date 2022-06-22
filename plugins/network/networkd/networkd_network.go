// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package networkd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/jaypipes/ghw"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/pmd-nextgen/pkg/configfile"
	"github.com/pmd-nextgen/pkg/share"
	"github.com/pmd-nextgen/pkg/validator"
	"github.com/pmd-nextgen/pkg/web"
)

type MatchSection struct {
	Name string `json:"Name"`
}

type LinkSection struct {
	MTUBytes                string `json:"MTUBytes"`
	MACAddress              string `json:"MACAddress"`
	ARP                     string `json:"ARP"`
	Multicast               string `json:"Multicast"`
	AllMulticast            string `json:"AllMulticast"`
	Promiscuous             string `json:"Promiscuous"`
	Unmanaged               string `json:"Unmanaged"`
	Group                   string `json:"Group"`
	RequiredForOnline       string `json:"RequiredForOnline"`
	RequiredFamilyForOnline string `json:"RequiredFamilyForOnline"`
	ActivationPolicy        string `json:"ActivationPolicy"`
}

type NetworkSection struct {
	DHCP                string   `json:"DHCP"`
	DHCPServer          string   `json:"DHCPServer"`
	Address             string   `json:"Address"`
	Gateway             string   `json:"Gateway"`
	DNS                 []string `json:"DNS"`
	Domains             []string `json:"Domains"`
	NTP                 []string `json:"NTP"`
	IPv6AcceptRA        string   `json:"IPv6AcceptRA"`
	IPv6SendRA          string   `json:"IPv6SendRA"`
	LinkLocalAddressing string   `json:"LinkLocalAddressing"`
	MulticastDNS        string   `json:"MulticastDNS"`

	VLAN string `json:"VLAN"`
}
type AddressSection struct {
	Address string `json:"Address"`
	Peer    string `json:"Peer"`
	Label   string `json:"Label"`
	Scope   string `json:"Scope"`
}

type RouteSection struct {
	Gateway         string `json:"Gateway"`
	GatewayOnlink   string `json:"GatewayOnlink"`
	Destination     string `json:"Destination"`
	Source          string `json:"Source"`
	PreferredSource string `json:"PreferredSource"`
	Table           string `json:"Table"`
	Scope           string `json:"Scope"`
}

type DHCPv4Section struct {
	ClientIdentifier      string   `json:"ClientIdentifier"`
	VendorClassIdentifier string   `json:"VendorClassIdentifier"`
	DUIDType              string   `json:"DUIDType"`
	DUIDRawData           string   `json:"DUIDRawData"`
	IAID                  string   `json:"IAID"`
	RequestOptions        []string `json:"RequestOptions"`
	SendOption            string   `json:"SendOption"`
	UseDNS                string   `json:"UseDNS"`
	UseNTP                string   `json:"UseNTP"`
	UseSIP                string   `json:"UseSIP"`
	UseMTU                string   `json:"UseMTU"`
	UseHostname           string   `json:"UseHostname"`
	UseDomains            string   `json:"UseDomains"`
	UseRoutes             string   `json:"UseRoutes"`
	UseGateway            string   `json:"UseGateway"`
	UseTimezone           string   `json:"UseTimezone"`
}

type DHCPv6Section struct {
	MUDURL               string   `json:"MUDURL"`
	IAID                 string   `json:"IAID"`
	DUIDType             string   `json:"DUIDType"`
	DUIDRawData          string   `json:"DUIDRawData"`
	RequestOptions       []string `json:"RequestOptions"`
	SendOption           string   `json:"SendOption"`
	SendVendorOption     string   `json:"SendVendorOption"`
	UserClass            []string `json:"UserClass"`
	VendorClass          []string `json:"VendorClass"`
	PrefixDelegationHint string   `json:"PrefixDelegationHint"`
	UseAddress           string   `json:"UseAddress"`
	UseDelegatedPrefix   string   `json:"UseDelegatedPrefix"`
	UseDNS               string   `json:"UseDNS"`
	UseNTP               string   `json:"UseNTP"`
	UseHostname          string   `json:"UseHostname"`
	UseDomains           string   `json:"UseDomains"`
	WithoutRA            string   `json:"WithoutRA"`
}

type DHCPv4ServerSection struct {
	PoolOffset          string   `json:"PoolOffset"`
	PoolSize            string   `json:"PoolSize"`
	DefaultLeaseTimeSec string   `json:"DefaultLeaseTimeSec"`
	MaxLeaseTimeSec     string   `json:"MaxLeaseTimeSec"`
	DNS                 []string `json:"DNS"`
	EmitDNS             string   `json:"EmitDNS"`
	EmitNTP             string   `json:"EmitNTP"`
	EmitRouter          string   `json:"EmitRouter"`
}

type RoutingPolicyRuleSection struct {
	TypeOfService          string `json:"TypeOfService"`
	From                   string `json:"From"`
	To                     string `json:"To"`
	FirewallMark           string `json:"FirewallMark"`
	Table                  string `json:"Table"`
	Priority               string `json:"Priority"`
	IncomingInterface      string `json:"IncomingInterface"`
	OutgoingInterface      string `json:"OutgoingInterface"`
	SourcePort             string `json:"SourcePort"`
	DestinationPort        string `json:"DestinationPort"`
	IPProtocol             string `json:"IPProtocol"`
	InvertRule             string `json:"InvertRule"`
	Family                 string `json:"Family"`
	User                   string `json:"User"`
	SuppressPrefixLength   string `json:"SuppressPrefixLength"`
	SuppressInterfaceGroup string `json:"SuppressInterfaceGroup"`
	Type                   string `json:"Type"`
}

type IPv6SendRASection struct {
	RouterPreference string   `json:"RouterPreference"`
	EmitDNS          string   `json:"EmitDNS"`
	DNS              []string `json:"DNS"`
	EmitDomains      string   `json:"EmitDomains"`
	Domains          []string `json:"Domains"`
	DNSLifetimeSec   string   `json:"DNSLifetimeSec"`
}

type IPv6PrefixSection struct {
	Prefix               string `json:"Prefix"`
	PreferredLifetimeSec string `json:"PreferredLifetimeSec"`
	ValidLifetimeSec     string `json:"ValidLifetimeSec"`
	Assign               string `json:"Assign"`
}

type IPv6RoutePrefixSection struct {
	Route       string `json:"Route"`
	LifetimeSec string `json:"LifetimeSec"`
}

type Network struct {
	Link                      string                     `json:"Link"`
	LinkSection               LinkSection                `json:"LinkSection"`
	MatchSection              MatchSection               `json:"MatchSection"`
	NetworkSection            NetworkSection             `json:"NetworkSection"`
	DHCPv4Section             DHCPv4Section              `json:"DHCPv4Section"`
	DHCPv4ServerSection       DHCPv4ServerSection        `json:"DHCPv4ServerSection"`
	DHCPv6Section             DHCPv6Section              `json:"DHCPv6Section"`
	AddressSections           []AddressSection           `json:"AddressSections"`
	RouteSections             []RouteSection             `json:"RouteSections"`
	RoutingPolicyRuleSections []RoutingPolicyRuleSection `json:"RoutingPolicyRuleSections"`
	IPv6SendRASection         IPv6SendRASection          `json:"IPv6SendRASection"`
	IPv6PrefixSections        []IPv6PrefixSection        `json:"IPv6PrefixSections"`
	IPv6RoutePrefixSections   []IPv6RoutePrefixSection   `json:"IPv6RoutePrefixSections"`
}

type LinkDescribe struct {
	AddressState     string   `json:"AddressState"`
	AlternativeNames []string `json:"AlternativeNames"`
	CarrierState     string   `json:"CarrierState"`
	Driver           string   `json:"Driver"`
	IPv4AddressState string   `json:"IPv4AddressState"`
	IPv6AddressState string   `json:"IPv6AddressState"`
	Index            int      `json:"Index"`
	LinkFile         string   `json:"LinkFile"`
	Model            string   `json:"Model"`
	Name             string   `json:"Name"`
	OnlineState      string   `json:"OnlineState"`
	OperationalState string   `json:"OperationalState"`
	Path             string   `json:"Path"`
	SetupState       string   `json:"SetupState"`
	Type             string   `json:"Type"`
	Vendor           string   `json:"Vendor"`
	Manufacturer     string   `json:"Manufacturer"`
	NetworkFile      string   `json:"NetworkFile,omitempty"`
}

type LinksDescribe struct {
	Interfaces []LinkDescribe
}

type NetworkDescribe struct {
	AddressState     string   `json:"AddressState"`
	CarrierState     string   `json:"CarrierState"`
	OperationalState string   `json:"OperationalState"`
	OnlineState      string   `json:"OnlineState"`
	IPv4AddressState string   `json:"IPv4AddressState"`
	IPv6AddressState string   `json:"IPv6AddressState"`
	DNS              []string `json:"DNS"`
	Domains          []string `json:"Domains"`
	RouteDomains     []string `json:"RouteDomains"`
	NTP              []string `json:"NTP"`
}

func decodeNetworkJSONRequest(r *http.Request) (*Network, error) {
	n := Network{}
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		return nil, err
	}

	return &n, nil
}

func fillOneLink(link netlink.Link) LinkDescribe {
	l := LinkDescribe{
		Index: link.Attrs().Index,
		Name:  link.Attrs().Name,
		Type:  link.Attrs().EncapType,
	}

	l.AddressState, _ = ParseLinkAddressState(link.Attrs().Index)
	l.IPv4AddressState, _ = ParseLinkIPv4AddressState(link.Attrs().Index)
	l.IPv6AddressState, _ = ParseLinkIPv6AddressState(link.Attrs().Index)
	l.CarrierState, _ = ParseLinkCarrierState(link.Attrs().Index)
	l.OnlineState, _ = ParseLinkOnlineState(link.Attrs().Index)
	l.OperationalState, _ = ParseLinkOperationalState(link.Attrs().Index)
	l.SetupState, _ = ParseLinkSetupState(link.Attrs().Index)
	l.NetworkFile, _ = ParseLinkNetworkFile(link.Attrs().Index)

	c, err := configfile.ParseKeyFromSectionString(path.Join("/sys/class/net", link.Attrs().Name, "device/uevent"), "", "PCI_SLOT_NAME")
	if err == nil {
		pci, err := ghw.PCI()
		if err == nil {
			dev := pci.GetDevice(c)

			l.Model = dev.Product.Name
			l.Vendor = dev.Vendor.Name
			l.Path = "pci-" + dev.Address
		}
	}

	driver, err := configfile.ParseKeyFromSectionString(path.Join("/sys/class/net", link.Attrs().Name, "device/uevent"), "", "DRIVER")
	if err == nil {
		l.Driver = driver
	}

	return l
}

func buildLinkMessageFallback() (*LinksDescribe, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	linkDesc := LinksDescribe{}
	for _, l := range links {
		linkDesc.Interfaces = append(linkDesc.Interfaces, fillOneLink(l))
	}

	return &linkDesc, nil
}

func AcquireLinks(ctx context.Context) (*LinksDescribe, error) {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return nil, err
	}
	defer c.Close()

	links, err := c.DBusLinkDescribe(ctx)
	if err != nil {
		return buildLinkMessageFallback()
	}

	return links, nil
}

func AcquireNetworkState(ctx context.Context) (*NetworkDescribe, error) {
	n := NetworkDescribe{}
	n.AddressState, _ = ParseNetworkAddressState()
	n.IPv4AddressState, _ = ParseNetworkIPv4AddressState()
	n.IPv6AddressState, _ = ParseNetworkIPv6AddressState()
	n.CarrierState, _ = ParseNetworkCarrierState()
	n.OnlineState, _ = ParseNetworkOnlineState()
	n.OperationalState, _ = ParseNetworkOperationalState()
	n.DNS, _ = ParseNetworkDNS()
	n.Domains, _ = ParseNetworkDomains()
	n.RouteDomains, _ = ParseNetworkRouteDomains()
	n.NTP, _ = ParseNetworkNTP()

	return &n, nil
}

func (n *Network) buildNetworkSection(m *configfile.Meta) error {
	if !validator.IsEmpty(n.NetworkSection.DHCP) {
		if validator.IsDHCP(n.NetworkSection.DHCP) {
			m.SetKeySectionString("Network", "DHCP", n.NetworkSection.DHCP)
		} else {
			log.Errorf("Failed to parse DHCP='%s'", n.NetworkSection.DHCP)
			return fmt.Errorf("invalid DHCP='%s'", n.NetworkSection.DHCP)
		}
	}

	if !validator.IsEmpty(n.NetworkSection.DHCPServer) {
		if !validator.IsBool(n.NetworkSection.DHCPServer) {
			log.Errorf("Failed to parse DHCPServer='%s'", n.NetworkSection.DHCPServer)
			return fmt.Errorf("invalid DHCPServer='%s'", n.NetworkSection.DHCPServer)
		}
		m.SetKeySectionString("Network", "DHCPServer", n.NetworkSection.DHCPServer)
	}

	if !validator.IsEmpty(n.NetworkSection.LinkLocalAddressing) {
		if validator.IsLinkLocalAddressing(n.NetworkSection.LinkLocalAddressing) {
			m.SetKeySectionString("Network", "LinkLocalAddressing", n.NetworkSection.LinkLocalAddressing)
		} else {
			log.Errorf("Failed to parse LinkLocalAddressing='%s'", n.NetworkSection.LinkLocalAddressing)
			return fmt.Errorf("invalid LinkLocalAddressing='%s'", n.NetworkSection.LinkLocalAddressing)
		}
	}

	if !validator.IsEmpty(n.NetworkSection.MulticastDNS) && validator.IsMulticastDNS(n.NetworkSection.MulticastDNS) {
		m.SetKeySectionString("Network", "MulticastDNS", n.NetworkSection.MulticastDNS)
	}

	if !validator.IsEmpty(n.NetworkSection.Address) {
		if validator.IsIP(n.NetworkSection.Address) {
			m.SetKeySectionString("Network", "Address", n.NetworkSection.Address)
		} else {
			log.Errorf("Failed to parse Address='%s'", n.NetworkSection.Address)
			return fmt.Errorf("invalid Address='%s'", n.NetworkSection.Address)
		}
	}

	if !validator.IsEmpty(n.NetworkSection.Gateway) {
		if validator.IsIP(n.NetworkSection.Gateway) {
			m.SetKeySectionString("Network", "Gateway", n.NetworkSection.Gateway)
		} else {
			log.Errorf("Failed to parse Gateway='%s'", n.NetworkSection.Gateway)
			return fmt.Errorf("invalid Gateway='%s'", n.NetworkSection.Gateway)
		}
	}

	if !validator.IsArrayEmpty(n.NetworkSection.DNS) {
		for _, dns := range n.NetworkSection.DNS {
			if !validator.IsIP(dns) {
				log.Errorf("Failed to parse DNS='%s'", dns)
				return fmt.Errorf("invalid DNS='%s'", dns)
			}
		}
		s := m.GetKeySectionString("Network", "DNS")
		t := share.UniqueSlices(strings.Split(s, " "), n.NetworkSection.DNS)
		m.SetKeySectionString("Network", "DNS", strings.Join(t[:], " "))
	}

	if !validator.IsArrayEmpty(n.NetworkSection.Domains) {
		s := m.GetKeySectionString("Network", "Domains")
		t := share.UniqueSlices(strings.Split(s, " "), n.NetworkSection.Domains)
		m.SetKeySectionString("Network", "Domains", strings.Join(t[:], " "))
	}

	if !validator.IsArrayEmpty(n.NetworkSection.NTP) {
		s := m.GetKeySectionString("Network", "NTP")
		t := share.UniqueSlices(strings.Split(s, " "), n.NetworkSection.NTP)
		m.SetKeySectionString("Network", "NTP", strings.Join(t[:], " "))
	}

	if !validator.IsEmpty(n.NetworkSection.IPv6AcceptRA) && validator.IsBool(n.NetworkSection.IPv6AcceptRA) {
		m.SetKeySectionString("Network", "IPv6AcceptRA", n.NetworkSection.IPv6AcceptRA)
	}

	if !validator.IsEmpty(n.NetworkSection.IPv6SendRA) && validator.IsBool(n.NetworkSection.IPv6SendRA) {
		m.SetKeySectionString("Network", "IPv6SendRA", n.NetworkSection.IPv6SendRA)
	}

	return nil
}

func (n *Network) removeNetworkSection(m *configfile.Meta) error {
	if !validator.IsEmpty(n.NetworkSection.DHCPServer) && validator.IsBool(n.NetworkSection.DHCPServer) {
		m.SetKeySectionString("Network", "DHCPServer", n.NetworkSection.DHCPServer)
	}

	if !validator.IsEmpty(n.NetworkSection.Address) {
		if validator.IsIP(n.NetworkSection.Address) {
			m.RemoveKeyFromSectionString("Network", "Address", n.NetworkSection.Address)
		}
	}

	if !validator.IsEmpty(n.NetworkSection.Gateway) {
		if validator.IsIP(n.NetworkSection.Gateway) {
			m.RemoveKeyFromSectionString("Network", "Gateway", n.NetworkSection.Gateway)
		}
	}

	if !validator.IsEmpty(n.NetworkSection.IPv6AcceptRA) && validator.IsBool(n.NetworkSection.IPv6AcceptRA) {
		m.RemoveKeyFromSectionString("Network", "IPv6AcceptRA", n.NetworkSection.IPv6AcceptRA)
	}

	if !validator.IsEmpty(n.NetworkSection.LinkLocalAddressing) {
		if validator.IsLinkLocalAddressing(n.NetworkSection.LinkLocalAddressing) {
			m.RemoveKeyFromSectionString("Network", "LinkLocalAddressing", n.NetworkSection.LinkLocalAddressing)
		}
	}

	if !validator.IsEmpty(n.NetworkSection.MulticastDNS) && validator.IsBool(n.NetworkSection.MulticastDNS) {
		m.RemoveKeyFromSectionString("Network", "MulticastDNS", n.NetworkSection.MulticastDNS)
	}

	if !validator.IsArrayEmpty(n.NetworkSection.Domains) {
		s := m.GetKeySectionString("Network", "Domains")
		t, err := share.StringDeleteAllSlice(strings.Split(s, " "), n.NetworkSection.Domains)
		if err != nil {
			return err
		}
		m.SetKeySectionString("Network", "Domains", strings.Join(t[:], " "))
	}

	if !validator.IsArrayEmpty(n.NetworkSection.DNS) {
		s := m.GetKeySectionString("Network", "DNS")
		t, err := share.StringDeleteAllSlice(strings.Split(s, " "), n.NetworkSection.DNS)
		if err != nil {
			return err
		}
		m.SetKeySectionString("Network", "DNS", strings.Join(t[:], " "))
	}

	if !validator.IsArrayEmpty(n.NetworkSection.NTP) {
		s := m.GetKeySectionString("Network", "NTP")
		t, err := share.StringDeleteAllSlice(strings.Split(s, " "), n.NetworkSection.NTP)
		if err != nil {
			return err
		}
		m.SetKeySectionString("Network", "NTP", strings.Join(t[:], " "))
	}

	if !validator.IsEmpty(n.NetworkSection.IPv6SendRA) && validator.IsBool(n.NetworkSection.IPv6SendRA) {
		m.SetKeySectionString("Network", "IPv6SendRA", n.NetworkSection.IPv6SendRA)
	}

	return nil
}

func (n *Network) buildLinkSection(m *configfile.Meta) error {
	if !validator.IsEmpty(n.LinkSection.MTUBytes) {
		if validator.IsUint32(n.LinkSection.MTUBytes) {
			m.SetKeySectionString("Link", "MTUBytes", n.LinkSection.MTUBytes)
		} else {
			log.Errorf("Invalid MTU='%s'", n.LinkSection.MTUBytes)
			return fmt.Errorf("invalid MTU='%s'", n.LinkSection.MTUBytes)
		}
	}

	if !validator.IsEmpty(n.LinkSection.MACAddress) {
		if validator.IsNotMAC(n.LinkSection.MACAddress) {
			log.Errorf("Failed to parse Mac='%s'", n.LinkSection.MACAddress)
			return fmt.Errorf("invalid Address='%s'", n.LinkSection.MACAddress)

		} else {
			m.SetKeySectionString("Link", "MACAddress", n.LinkSection.MACAddress)
		}
	}

	if !validator.IsEmpty(n.LinkSection.ARP) && validator.IsBool(n.LinkSection.ARP) {
		m.SetKeySectionString("Link", "ARP", n.LinkSection.ARP)
	}

	if !validator.IsEmpty(n.LinkSection.Multicast) && validator.IsBool(n.LinkSection.Multicast) {
		m.SetKeySectionString("Link", "Multicast", n.LinkSection.Multicast)
	}

	if !validator.IsEmpty(n.LinkSection.AllMulticast) && validator.IsBool(n.LinkSection.AllMulticast) {
		m.SetKeySectionString("Link", "AllMulticast", n.LinkSection.AllMulticast)
	}

	if !validator.IsEmpty(n.LinkSection.Promiscuous) && validator.IsBool(n.LinkSection.Promiscuous) {
		m.SetKeySectionString("Link", "Promiscuous", n.LinkSection.Promiscuous)
	}

	if !validator.IsEmpty(n.LinkSection.Unmanaged) && validator.IsBool(n.LinkSection.Unmanaged) {
		m.SetKeySectionString("Link", "Unmanaged", n.LinkSection.Unmanaged)
	}

	if !validator.IsEmpty(n.LinkSection.Group) {
		if !validator.IsLinkGroup(n.LinkSection.Group) {
			log.Errorf("Failed to parse Group='%s'", n.LinkSection.Group)
			return fmt.Errorf("invalid group='%s'", n.LinkSection.Group)

		}
		m.SetKeySectionString("Link", "Group", n.LinkSection.Group)
	}

	if !validator.IsEmpty(n.LinkSection.RequiredForOnline) && validator.IsBool(n.LinkSection.RequiredForOnline) {
		m.SetKeySectionString("Link", "RequiredForOnline", n.LinkSection.RequiredForOnline)
	}

	if !validator.IsEmpty(n.LinkSection.RequiredFamilyForOnline) {
		if !validator.IsAddressFamily(n.LinkSection.RequiredFamilyForOnline) {
			log.Errorf("Failed to parse RequiredFamilyForOnline='%s'", n.LinkSection.RequiredFamilyForOnline)
			return fmt.Errorf("invalid online family='%s'", n.LinkSection.RequiredFamilyForOnline)

		}
		m.SetKeySectionString("Link", "RequiredFamilyForOnline", n.LinkSection.RequiredFamilyForOnline)
	}

	if !validator.IsEmpty(n.LinkSection.ActivationPolicy) {
		if !validator.IsLinkActivationPolicy(n.LinkSection.ActivationPolicy) {
			log.Errorf("Failed to parse ActivationPolicy='%s'", n.LinkSection.ActivationPolicy)
			return fmt.Errorf("invalid activation policy='%s'", n.LinkSection.ActivationPolicy)

		}
		m.SetKeySectionString("Link", "ActivationPolicy", n.LinkSection.ActivationPolicy)
	}

	return nil
}

func (n *Network) buildDHCPv4Section(m *configfile.Meta) error {
	if !validator.IsEmpty(n.DHCPv4Section.ClientIdentifier) &&
		validator.IsDHCPv4ClientIdentifier(n.DHCPv4Section.ClientIdentifier) {
		m.SetKeySectionString("DHCPv4", "ClientIdentifier", n.DHCPv4Section.ClientIdentifier)
	}

	if !validator.IsEmpty(n.DHCPv4Section.VendorClassIdentifier) {
		m.SetKeySectionString("DHCPv4", "VendorClassIdentifier", n.DHCPv4Section.VendorClassIdentifier)
	}

	if !validator.IsEmpty(n.DHCPv4Section.IAID) && validator.IsUint32(n.DHCPv4Section.IAID) {
		m.SetKeySectionString("DHCPv4", "IAID", n.DHCPv4Section.IAID)
	}

	if !validator.IsEmpty(n.DHCPv4Section.DUIDType) && validator.IsDHCPDUIDType(n.DHCPv4Section.DUIDType) {
		m.SetKeySectionString("DHCPv4", "DUIDType", n.DHCPv4Section.DUIDType)
	}

	if !validator.IsEmpty(n.DHCPv4Section.DUIDRawData) {
		m.SetKeySectionString("DHCPv4", "DUIDRawData", n.DHCPv4Section.DUIDRawData)
	}

	if !validator.IsArrayEmpty(n.DHCPv4Section.RequestOptions) {
		for _, o := range n.DHCPv4Section.RequestOptions {
			if !validator.IsUint8(o) {
				log.Errorf("Failed to create DHCPv4Section. Invalid RequestOptions='%s'", o)
				return fmt.Errorf("invalid options='%s'", o)
			}
		}
		m.SetKeySectionString("DHCPv4", "RequestOptions", strings.Join(n.DHCPv4Section.RequestOptions, " "))
	}

	if !validator.IsEmpty(n.DHCPv4Section.SendOption) && validator.IsDHCPv4SendOption(n.DHCPv4Section.SendOption) {
		m.SetKeySectionString("DHCPv4", "SendOption", n.DHCPv4Section.SendOption)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseDNS) && validator.IsBool(n.DHCPv4Section.UseDNS) {
		m.SetKeySectionString("DHCPv4", "UseDNS", n.DHCPv4Section.UseDNS)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseNTP) && validator.IsBool(n.DHCPv4Section.UseNTP) {
		m.SetKeySectionString("DHCPv4", "UseNTP", n.DHCPv4Section.UseNTP)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseSIP) && validator.IsBool(n.DHCPv4Section.UseSIP) {
		m.SetKeySectionString("DHCPv4", "UseSIP", n.DHCPv4Section.UseSIP)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseMTU) && validator.IsBool(n.DHCPv4Section.UseMTU) {
		m.SetKeySectionString("DHCPv4", "UseMTU", n.DHCPv4Section.UseMTU)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseHostname) && validator.IsBool(n.DHCPv4Section.UseHostname) {
		m.SetKeySectionString("DHCPv4", "UseHostname", n.DHCPv4Section.UseHostname)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseDomains) && validator.IsBool(n.DHCPv4Section.UseDomains) {
		m.SetKeySectionString("DHCPv4", "UseDomains", n.DHCPv4Section.UseDomains)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseRoutes) && validator.IsBool(n.DHCPv4Section.UseRoutes) {
		m.SetKeySectionString("DHCPv4", "UseRoutes", n.DHCPv4Section.UseRoutes)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseGateway) && validator.IsBool(n.DHCPv4Section.UseGateway) {
		m.SetKeySectionString("DHCPv4", "UseGateway", n.DHCPv4Section.UseGateway)
	}

	if !validator.IsEmpty(n.DHCPv4Section.UseTimezone) && validator.IsBool(n.DHCPv4Section.UseTimezone) {
		m.SetKeySectionString("DHCPv4", "UseTimezone", n.DHCPv4Section.UseTimezone)
	}

	return nil
}

func (n *Network) buildDHCPv6Section(m *configfile.Meta) error {
	if !validator.IsEmpty(n.DHCPv6Section.MUDURL) {
		m.SetKeySectionString("DHCPv6", "MUDURL", n.DHCPv6Section.MUDURL)
	}

	if !validator.IsEmpty(n.DHCPv6Section.IAID) && validator.IsUint32(n.DHCPv6Section.IAID) {
		m.SetKeySectionString("DHCPv6", "IAID", n.DHCPv6Section.IAID)
	}

	if !validator.IsEmpty(n.DHCPv6Section.DUIDType) && validator.IsDHCPDUIDType(n.DHCPv6Section.DUIDType) {
		m.SetKeySectionString("DHCPv6", "DUIDType", n.DHCPv6Section.DUIDType)
	}

	if !validator.IsEmpty(n.DHCPv6Section.DUIDRawData) {
		m.SetKeySectionString("DHCPv6", "DUIDRawData", n.DHCPv6Section.DUIDRawData)
	}

	if !validator.IsArrayEmpty(n.DHCPv6Section.RequestOptions) {
		for _, o := range n.DHCPv6Section.RequestOptions {
			if !validator.IsUint8(o) {
				log.Errorf("Failed to create DHCPv6Section. Invalid RequestOptions='%s'", o)
				return fmt.Errorf("invalid options='%s'", o)
			}
		}
		m.SetKeySectionString("DHCPv6", "RequestOptions", strings.Join(n.DHCPv6Section.RequestOptions, " "))
	}

	if !validator.IsEmpty(n.DHCPv6Section.SendOption) && validator.IsUint16(n.DHCPv6Section.SendOption) {
		m.SetKeySectionString("DHCPv6", "SendOption", n.DHCPv6Section.SendOption)
	}

	if !validator.IsEmpty(n.DHCPv6Section.SendVendorOption) && validator.IsDHCPv6SendVendorOption(n.DHCPv6Section.SendVendorOption) {
		m.SetKeySectionString("DHCPv6", "SendVendorOption", strings.Replace(n.DHCPv6Section.SendVendorOption, ",", ":", -1))
	}

	if !validator.IsArrayEmpty(n.DHCPv6Section.UserClass) {
		m.SetKeySectionString("DHCPv6", "UserClass", strings.Join(n.DHCPv6Section.UserClass, " "))
	}

	if !validator.IsArrayEmpty(n.DHCPv6Section.VendorClass) {
		m.SetKeySectionString("DHCPv6", "VendorClass", strings.Join(n.DHCPv6Section.VendorClass, " "))
	}

	if !validator.IsEmpty(n.DHCPv6Section.PrefixDelegationHint) && validator.IsIP(n.DHCPv6Section.PrefixDelegationHint) {
		m.SetKeySectionString("DHCPv6", "PrefixDelegationHint", n.DHCPv6Section.PrefixDelegationHint)
	}

	if !validator.IsEmpty(n.DHCPv6Section.UseAddress) && validator.IsBool(n.DHCPv6Section.UseAddress) {
		m.SetKeySectionString("DHCPv6", "UseAddress", n.DHCPv6Section.UseAddress)
	}

	if !validator.IsEmpty(n.DHCPv6Section.UseDelegatedPrefix) && validator.IsBool(n.DHCPv6Section.UseDelegatedPrefix) {
		m.SetKeySectionString("DHCPv6", "UseDelegatedPrefix", n.DHCPv6Section.UseDelegatedPrefix)
	}

	if !validator.IsEmpty(n.DHCPv6Section.UseDNS) && validator.IsBool(n.DHCPv6Section.UseDNS) {
		m.SetKeySectionString("DHCPv6", "UseDNS", n.DHCPv6Section.UseDNS)
	}

	if !validator.IsEmpty(n.DHCPv6Section.UseNTP) && validator.IsBool(n.DHCPv6Section.UseNTP) {
		m.SetKeySectionString("DHCPv6", "UseNTP", n.DHCPv6Section.UseNTP)
	}

	if !validator.IsEmpty(n.DHCPv6Section.UseHostname) && validator.IsBool(n.DHCPv6Section.UseHostname) {
		m.SetKeySectionString("DHCPv6", "UseHostname", n.DHCPv6Section.UseHostname)
	}

	if !validator.IsEmpty(n.DHCPv6Section.UseDomains) && validator.IsBool(n.DHCPv6Section.UseDomains) {
		m.SetKeySectionString("DHCPv6", "UseDomains", n.DHCPv6Section.UseDomains)
	}

	if !validator.IsEmpty(n.DHCPv6Section.WithoutRA) && validator.IsDHCPv6WithoutRA(n.DHCPv6Section.WithoutRA) {
		m.SetKeySectionString("DHCPv6", "WithoutRA", n.DHCPv6Section.WithoutRA)
	}

	return nil
}

func (n *Network) buildDHCPv4ServerSection(m *configfile.Meta) error {
	if !validator.IsEmpty(n.DHCPv4ServerSection.PoolOffset) && validator.IsUint32(n.DHCPv4ServerSection.PoolOffset) {
		m.SetKeySectionString("DHCPServer", "PoolOffset", n.DHCPv4ServerSection.PoolOffset)
	}

	if !validator.IsEmpty(n.DHCPv4ServerSection.PoolSize) && validator.IsUint32(n.DHCPv4ServerSection.PoolSize) {
		m.SetKeySectionString("DHCPServer", "PoolSize", n.DHCPv4ServerSection.PoolSize)
	}

	if !validator.IsEmpty(n.DHCPv4ServerSection.DefaultLeaseTimeSec) && validator.IsUint32(n.DHCPv4ServerSection.DefaultLeaseTimeSec) {
		m.SetKeySectionString("DHCPServer", "DefaultLeaseTimeSec", n.DHCPv4ServerSection.DefaultLeaseTimeSec)
	}

	if !validator.IsEmpty(n.DHCPv4ServerSection.MaxLeaseTimeSec) && validator.IsUint32(n.DHCPv4ServerSection.MaxLeaseTimeSec) {
		m.SetKeySectionString("DHCPServer", "MaxLeaseTimeSec", n.DHCPv4ServerSection.MaxLeaseTimeSec)
	}

	if !validator.IsArrayEmpty(n.DHCPv4ServerSection.DNS) {
		for _, d := range n.DHCPv4ServerSection.DNS {
			if !validator.IsIP(d) {
				log.Errorf("Failed to create DHCPServer. Invalid DNS='%s'", d)
				return fmt.Errorf("invalid dns='%s'", d)
			}
		}
		m.SetKeySectionString("DHCPServer", "DNS", strings.Join(n.DHCPv4ServerSection.DNS, " "))
	}

	if !validator.IsEmpty(n.DHCPv4ServerSection.EmitDNS) && validator.IsBool(n.DHCPv4ServerSection.EmitDNS) {
		m.SetKeySectionString("DHCPServer", "EmitDNS", n.DHCPv4ServerSection.EmitDNS)
	}

	if !validator.IsEmpty(n.DHCPv4ServerSection.EmitNTP) && validator.IsBool(n.DHCPv4ServerSection.EmitNTP) {
		m.SetKeySectionString("DHCPServer", "EmitNTP", n.DHCPv4ServerSection.EmitNTP)
	}

	if !validator.IsEmpty(n.DHCPv4ServerSection.EmitRouter) && validator.IsBool(n.DHCPv4ServerSection.EmitRouter) {
		m.SetKeySectionString("DHCPServer", "EmitRouter", n.DHCPv4ServerSection.EmitRouter)
	}

	return nil
}

func (n *Network) buildAddressSection(m *configfile.Meta) error {
	for _, a := range n.AddressSections {
		if err := m.NewSection("Address"); err != nil {
			return err
		}

		if !validator.IsEmpty(a.Address) {
			if validator.IsIP(a.Address) {
				m.SetKeyToNewSectionString("Address", a.Address)
			} else {
				log.Errorf("Failed to parse Address='%s'", a.Address)
				return fmt.Errorf("invalid Address='%s'", a.Address)
			}
		}

		if !validator.IsEmpty(a.Peer) {
			if validator.IsIP(a.Peer) {
				m.SetKeyToNewSectionString("Peer", a.Peer)
			} else {
				log.Errorf("Failed to parse Peer='%s'", a.Peer)
				return fmt.Errorf("invalid Peer='%s'", a.Peer)
			}
		}

		if !validator.IsEmpty(a.Label) {
			m.SetKeyToNewSectionString("Label", a.Label)
		}

		if !validator.IsEmpty(a.Scope) && validator.IsScope(a.Scope) {
			m.SetKeyToNewSectionString("Scope", a.Scope)
		}
	}

	return nil
}

func (n *Network) buildRouteSection(m *configfile.Meta) error {
	for _, rt := range n.RouteSections {
		if err := m.NewSection("Route"); err != nil {
			return err
		}

		if !validator.IsEmpty(rt.Gateway) {
			if validator.IsIP(rt.Gateway) {
				m.SetKeyToNewSectionString("Gateway", rt.Gateway)
			} else {
				log.Errorf("Failed to parse Gateway='%s'", rt.Gateway)
				return fmt.Errorf("invalid Gateway='%s'", rt.Gateway)
			}
		}

		if !validator.IsEmpty(rt.GatewayOnlink) {
			if !validator.IsBool(rt.GatewayOnlink) {
				log.Errorf("Failed to parse GatewayOnlink='%s'", rt.GatewayOnlink)
				return fmt.Errorf("invalid GatewayOnlink='%s'", rt.GatewayOnlink)
			}
			m.SetKeyToNewSectionString("GatewayOnlink", rt.GatewayOnlink)
		}

		if !validator.IsEmpty(rt.Destination) {
			if validator.IsIP(rt.Destination) {
				m.SetKeyToNewSectionString("Destination", rt.Destination)
			} else {
				log.Errorf("Failed to parse Destination='%s'", rt.Destination)
				return fmt.Errorf("invalid Destination='%s'", rt.Destination)
			}
		}

		if !validator.IsEmpty(rt.Source) {
			if validator.IsIP(rt.Source) {
				m.SetKeyToNewSectionString("Source", rt.Source)
			} else {
				log.Errorf("Failed to parse Source='%s'", rt.Source)
				return fmt.Errorf("invalid Source='%s'", rt.Source)
			}
		}

		if !validator.IsEmpty(rt.PreferredSource) {
			if validator.IsIP(rt.PreferredSource) {
				m.SetKeyToNewSectionString("PreferredSource", rt.PreferredSource)
			} else {
				log.Errorf("Failed to parse PreferredSource='%s'", rt.PreferredSource)
				return fmt.Errorf("invalid PreferredSource='%s'", rt.PreferredSource)
			}
		}

		if !validator.IsEmpty(rt.Table) && govalidator.IsInt(rt.Table) {
			m.SetKeyToNewSectionString("Table", rt.Table)
		}

		if !validator.IsEmpty(rt.Scope) && validator.IsScope(rt.Scope) {
			m.SetKeyToNewSectionString("Scope", rt.Scope)
		}
	}

	return nil
}

func (n *Network) buildRoutingPolicyRuleSection(m *configfile.Meta) error {
	for _, rtpr := range n.RoutingPolicyRuleSections {
		if err := m.NewSection("RoutingPolicyRule"); err != nil {
			return err
		}

		if !validator.IsEmpty(rtpr.TypeOfService) {
			if !validator.IsRoutingTypeOfService(rtpr.TypeOfService) {
				log.Errorf("Failed to parse TypeOfService='%s'", rtpr.TypeOfService)
				return fmt.Errorf("invalid TypeOfService='%s'", rtpr.TypeOfService)
			}
			m.SetKeyToNewSectionString("TypeOfService", rtpr.TypeOfService)
		}

		if !validator.IsEmpty(rtpr.From) {
			if !validator.IsIP(rtpr.From) {
				log.Errorf("Failed to parse From='%s'", rtpr.From)
				return fmt.Errorf("invalid From='%s'", rtpr.From)
			}
			m.SetKeyToNewSectionString("From", rtpr.From)
		}

		if !validator.IsEmpty(rtpr.To) {
			if !validator.IsIP(rtpr.To) {
				log.Errorf("Failed to parse To='%s'", rtpr.To)
				return fmt.Errorf("invalid To='%s'", rtpr.To)
			}
			m.SetKeyToNewSectionString("To", rtpr.To)
		}

		if !validator.IsEmpty(rtpr.FirewallMark) {
			if !validator.IsRoutingFirewallMark(rtpr.FirewallMark) {
				log.Errorf("Failed to parse FirewallMark='%s'", rtpr.FirewallMark)
				return fmt.Errorf("invalid FirewallMark='%s'", rtpr.FirewallMark)
			}
			m.SetKeyToNewSectionString("FirewallMark", rtpr.FirewallMark)
		}

		if !validator.IsEmpty(rtpr.Table) {
			if !validator.IsUint32(rtpr.Table) {
				log.Errorf("Failed to parse Table='%s'", rtpr.Table)
				return fmt.Errorf("invalid Table='%s'", rtpr.Table)
			}
			m.SetKeyToNewSectionString("Table", rtpr.Table)
		}

		if !validator.IsEmpty(rtpr.Priority) {
			if !validator.IsUint32(rtpr.Priority) {
				log.Errorf("Failed to parse Priority='%s'", rtpr.Priority)
				return fmt.Errorf("invalid Priority='%s'", rtpr.Priority)
			}
			m.SetKeyToNewSectionString("Priority", rtpr.Priority)
		}

		if !validator.IsEmpty(rtpr.IncomingInterface) {
			m.SetKeyToNewSectionString("IncomingInterface", rtpr.IncomingInterface)
		}

		if !validator.IsEmpty(rtpr.OutgoingInterface) {
			m.SetKeyToNewSectionString("OutgoingInterface", rtpr.OutgoingInterface)
		}

		if !validator.IsEmpty(rtpr.SourcePort) {
			if !validator.IsRoutingPort(rtpr.SourcePort) {
				log.Errorf("Failed to parse SourcePort='%s'", rtpr.SourcePort)
				return fmt.Errorf("invalid SourcePort='%s'", rtpr.SourcePort)
			}
			m.SetKeyToNewSectionString("SourcePort", rtpr.SourcePort)
		}

		if !validator.IsEmpty(rtpr.DestinationPort) {
			if !validator.IsRoutingPort(rtpr.DestinationPort) {
				log.Errorf("Failed to parse DestinationPort='%s'", rtpr.DestinationPort)
				return fmt.Errorf("invalid DestinationPort='%s'", rtpr.DestinationPort)
			}
			m.SetKeyToNewSectionString("DestinationPort", rtpr.DestinationPort)
		}

		if !validator.IsEmpty(rtpr.IPProtocol) {
			if !validator.IsRoutingIPProtocol(rtpr.IPProtocol) {
				log.Errorf("Failed to parse IPProtocol='%s'", rtpr.IPProtocol)
				return fmt.Errorf("invalid IPProtocol='%s'", rtpr.IPProtocol)
			}
			m.SetKeyToNewSectionString("IPProtocol", rtpr.IPProtocol)
		}

		if !validator.IsEmpty(rtpr.InvertRule) {
			if !validator.IsBool(rtpr.InvertRule) {
				log.Errorf("Failed to parse InvertRule='%s'", rtpr.InvertRule)
				return fmt.Errorf("invalid InvertRule='%s'", rtpr.InvertRule)
			}
			m.SetKeyToNewSectionString("InvertRule", rtpr.InvertRule)
		}

		if !validator.IsEmpty(rtpr.Family) {
			if !validator.IsAddressFamily(rtpr.Family) {
				log.Errorf("Failed to parse Family='%s'", rtpr.Family)
				return fmt.Errorf("invalid Family='%s'", rtpr.Family)
			}
			m.SetKeyToNewSectionString("Family", rtpr.Family)
		}

		if !validator.IsEmpty(rtpr.User) {
			if !validator.IsRoutingUser(rtpr.User) {
				log.Errorf("Failed to parse User='%s'", rtpr.User)
				return fmt.Errorf("invalid User='%s'", rtpr.User)
			}
			m.SetKeyToNewSectionString("User", rtpr.User)
		}

		if !validator.IsEmpty(rtpr.SuppressPrefixLength) {
			if !validator.IsRoutingSuppressPrefixLength(rtpr.SuppressPrefixLength) {
				log.Errorf("Failed to parse SuppressPrefixLength='%s'", rtpr.SuppressPrefixLength)
				return fmt.Errorf("invalid SuppressPrefixLength='%s'", rtpr.SuppressPrefixLength)
			}
			m.SetKeyToNewSectionString("SuppressPrefixLength", rtpr.SuppressPrefixLength)
		}

		if !validator.IsEmpty(rtpr.SuppressInterfaceGroup) {
			if !validator.IsUint32(rtpr.SuppressInterfaceGroup) {
				log.Errorf("Failed to parse SuppressInterfaceGroup='%s'", rtpr.SuppressInterfaceGroup)
				return fmt.Errorf("invalid SuppressInterfaceGroup='%s'", rtpr.SuppressInterfaceGroup)
			}
			m.SetKeyToNewSectionString("SuppressInterfaceGroup", rtpr.SuppressInterfaceGroup)
		}

		if !validator.IsEmpty(rtpr.Type) {
			if !validator.IsRoutingType(rtpr.Type) {
				log.Errorf("Failed to parse Type='%s'", rtpr.Type)
				return fmt.Errorf("invalid Type='%s'", rtpr.Type)
			}
			m.SetKeyToNewSectionString("Type", rtpr.Type)
		}

	}

	return nil
}

func (n *Network) buildIPv6SendRASection(m *configfile.Meta) error {
	if !validator.IsEmpty(n.IPv6SendRASection.RouterPreference) {
		if !validator.IsRouterPreference(n.IPv6SendRASection.RouterPreference) {
			log.Errorf("Failed to parse RouterPreference='%s'", n.IPv6SendRASection.RouterPreference)
			return fmt.Errorf("invalid RouterPreference='%s'", n.IPv6SendRASection.RouterPreference)
		}
		m.SetKeySectionString("IPv6SendRA", "RouterPreference", n.IPv6SendRASection.RouterPreference)
	}

	if !validator.IsEmpty(n.IPv6SendRASection.EmitDNS) && validator.IsBool(n.IPv6SendRASection.EmitDNS) {
		m.SetKeySectionString("IPv6SendRA", "EmitDNS", n.IPv6SendRASection.EmitDNS)
	}

	if !validator.IsArrayEmpty(n.IPv6SendRASection.DNS) {
		for _, d := range n.IPv6SendRASection.DNS {
			if !validator.IsIP(d) {
				log.Errorf("Failed to configure IPv6SendRA. Invalid DNS='%s'", d)
				return fmt.Errorf("invalid dns='%s'", d)
			}
		}
		m.SetKeySectionString("IPv6SendRA", "DNS", strings.Join(n.IPv6SendRASection.DNS, " "))
	}

	if !validator.IsEmpty(n.IPv6SendRASection.EmitDomains) && validator.IsBool(n.IPv6SendRASection.EmitDomains) {
		m.SetKeySectionString("IPv6SendRA", "EmitDomains", n.IPv6SendRASection.EmitDomains)
	}

	if !validator.IsArrayEmpty(n.IPv6SendRASection.Domains) {
		m.SetKeySectionString("IPv6SendRA", "Domains", strings.Join(n.IPv6SendRASection.Domains, " "))
	}

	if !validator.IsEmpty(n.IPv6SendRASection.DNSLifetimeSec) {
		if !validator.IsUint32(n.IPv6SendRASection.DNSLifetimeSec) {
			log.Errorf("Failed to parse DNSLifetimeSec='%s'", n.IPv6SendRASection.DNSLifetimeSec)
			return fmt.Errorf("invalid DNSLifetimeSec='%s'", n.IPv6SendRASection.DNSLifetimeSec)
		}
		m.SetKeySectionString("IPv6SendRA", "DNSLifetimeSec", n.IPv6SendRASection.DNSLifetimeSec)
	}

	return nil
}

func (n *Network) buildIPv6PrefixSection(m *configfile.Meta) error {
	for _, p := range n.IPv6PrefixSections {
		if err := m.NewSection("IPv6Prefix"); err != nil {
			return err
		}

		if !validator.IsEmpty(p.Prefix) {
			if !validator.IsIP(p.Prefix) {
				log.Errorf("Failed to parse Prefix='%s'", p.Prefix)
				return fmt.Errorf("invalid Prefix='%s'", p.Prefix)
			}
			m.SetKeyToNewSectionString("Prefix", p.Prefix)
		}

		if !validator.IsEmpty(p.PreferredLifetimeSec) {
			if !validator.IsUint32(p.PreferredLifetimeSec) {
				log.Errorf("Failed to parse PreferredLifetimeSec='%s'", p.PreferredLifetimeSec)
				return fmt.Errorf("invalid PreferredLifetimeSec='%s'", p.PreferredLifetimeSec)
			}
			m.SetKeyToNewSectionString("PreferredLifetimeSec", p.PreferredLifetimeSec)
		}

		if !validator.IsEmpty(p.ValidLifetimeSec) {
			if !validator.IsUint32(p.ValidLifetimeSec) {
				log.Errorf("Failed to parse ValidLifetimeSec='%s'", p.ValidLifetimeSec)
				return fmt.Errorf("invalid ValidLifetimeSec='%s'", p.ValidLifetimeSec)
			}
			m.SetKeyToNewSectionString("ValidLifetimeSec", p.ValidLifetimeSec)
		}

		if !validator.IsEmpty(p.Assign) && validator.IsBool(p.Assign) {
			m.SetKeyToNewSectionString("Assign", p.Assign)
		}
	}

	return nil
}

func (n *Network) buildIPv6RoutePrefixSection(m *configfile.Meta) error {
	for _, r := range n.IPv6RoutePrefixSections {
		if err := m.NewSection("IPv6RoutePrefix"); err != nil {
			return err
		}

		if !validator.IsEmpty(r.Route) {
			if !validator.IsIP(r.Route) {
				log.Errorf("Failed to parse Route='%s'", r.Route)
				return fmt.Errorf("invalid Route='%s'", r.Route)
			}
			m.SetKeyToNewSectionString("Route", r.Route)
		}

		if !validator.IsEmpty(r.LifetimeSec) {
			if !validator.IsUint32(r.LifetimeSec) {
				log.Errorf("Failed to parse LifetimeSec='%s'", r.LifetimeSec)
				return fmt.Errorf("invalid LifetimeSec='%s'", r.LifetimeSec)
			}
			m.SetKeyToNewSectionString("LifetimeSec", r.LifetimeSec)
		}
	}

	return nil
}

func (n *Network) removeAddressSection(m *configfile.Meta) error {
	for _, a := range n.AddressSections {
		if !validator.IsEmpty(a.Address) {
			if err := m.RemoveSection("Address", "Address", a.Address); err != nil {
				log.Errorf("Failed to remove Address='%s': %v", a.Address, err)
				return err
			}
		}
	}

	return nil
}

func (n *Network) removeRouteSection(m *configfile.Meta) error {
	for _, rt := range n.RouteSections {
		if !validator.IsEmpty(rt.Gateway) {
			if err := m.RemoveSection("Route", "Gateway", rt.Gateway); err != nil {
				log.Errorf("Failed to remove Gateway='%s': %v", rt.Gateway, err)
				return err
			}
		}

		if !validator.IsEmpty(rt.Destination) {
			if err := m.RemoveSection("Route", "Destination", rt.Destination); err != nil {
				log.Errorf("Failed to remove Destination='%s': %v", rt.Destination, err)
				return err
			}
		}
	}

	return nil
}

func (n *Network) removeRoutingPolicyRuleSection(m *configfile.Meta) error {
	for _, rtpr := range n.RoutingPolicyRuleSections {
		if !validator.IsEmpty(rtpr.TypeOfService) {
			if err := m.RemoveSection("RoutingPolicyRule", "TypeOfService", rtpr.TypeOfService); err != nil {
				log.Errorf("Failed to remove TypeOfService='%s': %v", rtpr.TypeOfService, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.From) {
			if err := m.RemoveSection("RoutingPolicyRule", "From", rtpr.From); err != nil {
				log.Errorf("Failed to remove From='%s': %v", rtpr.From, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.To) {
			if err := m.RemoveSection("RoutingPolicyRule", "To", rtpr.To); err != nil {
				log.Errorf("Failed to remove To='%s': %v", rtpr.To, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.FirewallMark) {
			if err := m.RemoveSection("RoutingPolicyRule", "FirewallMark", rtpr.FirewallMark); err != nil {
				log.Errorf("Failed to remove FirewallMark='%s': %v", rtpr.FirewallMark, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.Table) {
			if err := m.RemoveSection("RoutingPolicyRule", "Table", rtpr.Table); err != nil {
				log.Errorf("Failed to remove Table='%s': %v", rtpr.Table, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.Priority) {
			if err := m.RemoveSection("RoutingPolicyRule", "Priority", rtpr.Priority); err != nil {
				log.Errorf("Failed to remove Priority='%s': %v", rtpr.Priority, err)
				return err
			}
		}
		if !validator.IsEmpty(rtpr.IncomingInterface) {
			if err := m.RemoveSection("RoutingPolicyRule", "IncomingInterface", rtpr.IncomingInterface); err != nil {
				log.Errorf("Failed to remove IncomingInterface='%s': %v", rtpr.IncomingInterface, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.OutgoingInterface) {
			if err := m.RemoveSection("RoutingPolicyRule", "OutgoingInterface", rtpr.OutgoingInterface); err != nil {
				log.Errorf("Failed to remove OutgoingInterface='%s': %v", rtpr.OutgoingInterface, err)
				return err
			}
		}
		if !validator.IsEmpty(rtpr.SourcePort) {
			if err := m.RemoveSection("RoutingPolicyRule", "SourcePort", rtpr.SourcePort); err != nil {
				log.Errorf("Failed to remove SourcePort='%s': %v", rtpr.SourcePort, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.DestinationPort) {
			if err := m.RemoveSection("RoutingPolicyRule", "DestinationPort", rtpr.DestinationPort); err != nil {
				log.Errorf("Failed to remove DestinationPort='%s': %v", rtpr.DestinationPort, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.IPProtocol) {
			if err := m.RemoveSection("RoutingPolicyRule", "IPProtocol", rtpr.IPProtocol); err != nil {
				log.Errorf("Failed to remove IPProtocol='%s': %v", rtpr.IPProtocol, err)
				return err
			}
		}
		if !validator.IsEmpty(rtpr.InvertRule) {
			if err := m.RemoveSection("RoutingPolicyRule", "InvertRule", rtpr.InvertRule); err != nil {
				log.Errorf("Failed to remove InvertRule='%s': %v", rtpr.InvertRule, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.Family) {
			if err := m.RemoveSection("RoutingPolicyRule", "Family", rtpr.Family); err != nil {
				log.Errorf("Failed to remove Family='%s': %v", rtpr.Family, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.User) {
			if err := m.RemoveSection("RoutingPolicyRule", "User", rtpr.User); err != nil {
				log.Errorf("Failed to remove User='%s': %v", rtpr.User, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.SuppressPrefixLength) {
			if err := m.RemoveSection("RoutingPolicyRule", "SuppressPrefixLength", rtpr.SuppressPrefixLength); err != nil {
				log.Errorf("Failed to remove SuppressPrefixLength='%s': %v", rtpr.SuppressPrefixLength, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.SuppressInterfaceGroup) {
			if err := m.RemoveSection("RoutingPolicyRule", "SuppressInterfaceGroup", rtpr.SuppressInterfaceGroup); err != nil {
				log.Errorf("Failed to remove SuppressInterfaceGroup='%s': %v", rtpr.SuppressInterfaceGroup, err)
				return err
			}
		}

		if !validator.IsEmpty(rtpr.Type) {
			if err := m.RemoveSection("RoutingPolicyRule", "Type", rtpr.Type); err != nil {
				log.Errorf("Failed to remove Type='%s': %v", rtpr.Type, err)
				return err
			}
		}

	}

	return nil
}

func (n *Network) removeDHCPv4ServerSection(m *configfile.Meta) error {
	if s := m.GetKeySectionString("Network", "DHCPServer"); s == "no" {
		if err := m.RemoveSection("DHCPServer", "", ""); err != nil {
			log.Errorf("Failed to remove DHCPServer: %v", err)
			return err
		}
	}

	return nil
}

func (n *Network) removeIPv6SendRASection(m *configfile.Meta) error {
	if s := m.GetKeySectionString("Network", "IPv6SendRA"); s == "no" {
		if err := m.RemoveSection("IPv6SendRA", "", ""); err != nil {
			log.Errorf("Failed to remove IPv6SendRA: %v", err)
			return err
		}
	}

	return nil
}

func (n *Network) removeIPv6PrefixSection(m *configfile.Meta) error {
	if s := m.GetKeySectionString("Network", "IPv6SendRA"); s == "no" {
		if err := m.RemoveSection("IPv6Prefix", "", ""); err != nil {
			log.Errorf("Failed to remove IPv6Prefix: %v", err)
			return err
		}
	}

	return nil
}

func (n *Network) removeIPv6RoutePrefixSection(m *configfile.Meta) error {
	if s := m.GetKeySectionString("Network", "IPv6SendRA"); s == "no" {
		if err := m.RemoveSection("IPv6RoutePrefix", "", ""); err != nil {
			log.Errorf("Failed to remove IPv6RoutePrefix: %v", err)
			return err
		}
	}

	return nil
}

func (n *Network) ConfigureNetwork(ctx context.Context, w http.ResponseWriter) error {
	m, err := CreateOrParseNetworkFile(n.Link)
	if err != nil {
		log.Errorf("Failed to parse network file for link='%s': %v", n.Link, err)
		return err
	}

	if err := n.buildNetworkSection(m); err != nil {
		return err
	}
	if err := n.buildLinkSection(m); err != nil {
		return err
	}
	if err := n.buildDHCPv4Section(m); err != nil {
		return err
	}
	if err := n.buildDHCPv4ServerSection(m); err != nil {
		return err
	}
	if err := n.buildDHCPv4Section(m); err != nil {
		return err
	}
	if err := n.buildDHCPv6Section(m); err != nil {
		return err
	}
	if err := n.buildAddressSection(m); err != nil {
		return err
	}
	if err := n.buildRouteSection(m); err != nil {
		return err
	}
	if err := n.buildRoutingPolicyRuleSection(m); err != nil {
		return err
	}
	if err := n.buildIPv6SendRASection(m); err != nil {
		return err
	}
	if err := n.buildIPv6PrefixSection(m); err != nil {
		return err
	}
	if err := n.buildIPv6RoutePrefixSection(m); err != nil {
		return err
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection with the system bus: %v", err)
		return err
	}
	defer c.Close()

	if err := c.DBusNetworkReload(ctx); err != nil {
		return err
	}

	return web.JSONResponse("configured", w)
}

func (n *Network) RemoveNetwork(ctx context.Context, w http.ResponseWriter) error {
	m, err := CreateOrParseNetworkFile(n.Link)
	if err != nil {
		log.Errorf("Failed to parse network file for link='%s': %v", n.Link, err)
		return err
	}

	if err := n.removeNetworkSection(m); err != nil {
		log.Errorf("Failed to remove key from network section: %v", err)
		return err
	}

	if err := n.removeAddressSection(m); err != nil {
		log.Errorf("Failed to remove address section: %v", err)
		return err
	}

	if err := n.removeRouteSection(m); err != nil {
		log.Errorf("Failed to remove route section: %v", err)
		return err
	}

	if err := n.removeRoutingPolicyRuleSection(m); err != nil {
		log.Errorf("Failed to remove routing Policy rule section: %v", err)
		return err
	}

	if err := n.removeDHCPv4ServerSection(m); err != nil {
		log.Errorf("Failed to remove dhcp server section: %v", err)
		return err
	}

	if err := n.removeIPv6SendRASection(m); err != nil {
		log.Errorf("Failed to remove IPv6SendRA section: %v", err)
		return err
	}

	if err := n.removeIPv6PrefixSection(m); err != nil {
		log.Errorf("Failed to remove IPv6Prefix section: %v", err)
		return err
	}

	if err := n.removeIPv6RoutePrefixSection(m); err != nil {
		log.Errorf("Failed to remove IPv6RoutePrefix section: %v", err)
		return err
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection with the system bus: %v", err)
		return err
	}
	defer c.Close()

	if err := c.DBusNetworkReload(ctx); err != nil {
		return err
	}

	return web.JSONResponse("removed", w)
}
