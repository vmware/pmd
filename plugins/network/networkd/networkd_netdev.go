// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package networkd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/vmware/pmd/pkg/configfile"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
)

type VLan struct {
	Id uint `json:"Id"`
}

type MacVLan struct {
	Mode                          string `json:"Mode"`
	SourceMACAddress              string `json:"SourceMACAddress"`
	BroadcastMulticastQueueLength string `json:"BroadcastMulticastQueueLength"`
}

type IpVLan struct {
	Mode  string `json:"Mode"`
	Flags string `json:"Flags"`
}

type VxLan struct {
	VNI             string `json:"VNI"`
	Remote          string `json:"Remote"`
	Local           string `json:"Local"`
	Group           string `json:"Group"`
	DestinationPort string `json:"DestinationPort"`
	Independent     string `json:"Independent"`
}

type Bond struct {
	Mode                         string `json:"Mode"`
	TransmitHashPolicy           string `json:"TransmitHashPolicy"`
	LACPTransmitRate             string `json:"LACPTransmitRate"`
	MIIMonitorSec                string `json:"MIIMonitorSec"`
	UpDelaySec                   int    `json:"UpDelaySec"`
	DownDelaySec                 int    `json:"DownDelaySec"`
	LearnPacketIntervalSec       int    `json:"LearnPacketIntervalSec"`
	AdSelect                     string `json:"AdSelect"`
	AdActorSystemPriority        int    `json:"AdActorSystemPriority"`
	AdUserPortKey                int    `json:"AdUserPortKey"`
	AdActorSystem                string `json:"AdActorSystem"`
	FailOverMACPolicy            string `json:"FailOverMACPolicy"`
	ARPValidate                  string `json:"ARPValidate"`
	ARPIntervalSec               int    `json:"ARPIntervalSec"`
	ARPIPTargets                 string `json:"ARPIPTargets"`
	ARPAllTargets                string `json:"ARPAllTargets"`
	PrimaryReselectPolicy        string `json:"PrimaryReselectPolicy"`
	ResendIGMP                   int    `json:"ResendIGMP"`
	PacketsPerSlave              int    `json:"PacketsPerSlave"`
	GratuitousARP                int    `json:"GratuitousARP"`
	AllSlavesActive              bool   `json:"AllSlavesActive"`
	DynamicTransmitLoadBalancing bool   `json:"DynamicTransmitLoadBalancing"`
	MinLinks                     int    `json:"MinLinks"`
}

type Bridge struct {
	HelloTimeSec         string `json:"HelloTimeSec"`
	MaxAgeSec            string `json:"MaxAgeSec"`
	ForwardDelaySec      string `json:"ForwardDelaySec"`
	AgeingTimeSec        string `json:"AgeingTimeSec"`
	Priority             int    `json:"Priority"`
	GroupForwardMask     int    `json:"GroupForwardMask"`
	DefaultPVID          int    `json:"DefaultPVID"`
	MulticastQuerier     bool   `json:"MulticastQuerier"`
	MulticastSnooping    bool   `json:"MulticastSnooping"`
	VLANFiltering        bool   `json:"VLANFiltering"`
	VLANProtocol         string `json:"VLANProtocol"`
	STP                  string `json:"STP"`
	MulticastIGMPVersion int    `json:"MulticastIGMPVersion"`
}

type WireGuard struct {
	PrivateKey     string `json:"PrivateKey"`
	PrivateKeyFile string `json:"PrivateKeyFile"`
	ListenPort     string `json:"ListenPort"`
	FirewallMark   string `json:"FirewallMark"`
	RouteTable     string `json:"RouteTable"`
	RouteMetric    string `json:"RouteMetric"`
}

type WireGuardPeer struct {
	PublicKey           string   `json:"PublicKey"`
	PresharedKey        string   `json:"PresharedKey"`
	PresharedKeyFile    string   `json:"PresharedKeyFile"`
	AllowedIPs          []string `json:"AllowedIPs"`
	Endpoint            string   `json:"Endpoint"`
	PersistentKeepalive string   `json:"PersistentKeepalive"`
	RouteTable          string   `json:"RouteTable"`
	RouteMetric         string   `json:"RouteMetric"`
}

type TunOrTap struct {
	MultiQueue  string `json:"MultiQueue"`
	PacketInfo  string `json:"PacketInfo"`
	VNetHeader  string `json:"VNetHeader"`
	User        string `json:"User"`
	Group       string `json:"Group"`
	KeepCarrier string `json:"KeepCarrier"`
}

type NetDev struct {
	Links []string `json:"Link"` // Master device

	MatchSection MatchSection `json:"MatchSection"`

	// [NetDev]
	Name        string `json:"Name"`
	Description string `json:"Description"`
	Kind        string `json:"Kind"`
	MTUBytes    string `json:"MTUBytes"`
	MACAddress  string `json:"MACAddress"`
	// [Kind]
	VLanSection          VLan          `json:"VLanSection"`
	MacVLanSection       MacVLan       `json:"MacVLanSection"`
	IpVLanSection        IpVLan        `json:"IpVLanSection"`
	VxLanSection         VxLan         `json:"VxLanSection"`
	BondSection          Bond          `json:"BondSection"`
	BridgeSection        Bridge        `json:"BridgeSection"`
	WireGuardSection     WireGuard     `json:"WireGuardSection"`
	WireGuardPeerSection WireGuardPeer `json:"WireGuardPeerSection"`
	TunOrTapSection      TunOrTap      `json:"TunOrTapSection"`
}

func netDevKindToNetworkKind(s string) string {
	var kind string
	switch s {
	case "vlan":
		kind = "VLAN"
	case "bond":
		kind = "Bond"
	case "bridge":
		kind = "Bridge"
	case "macvlan":
		kind = "MACVLAN"
	case "macvtap":
		kind = "MACVTAP"
	case "ipvlan":
		kind = "IPVLAN"
	case "ipvtap":
		kind = "IPVTAP"
	case "vxlan":
		kind = "VXLAN"
	case "wireguard":
		kind = "WireGuard"
	case "tun":
		kind = "Tun"
	case "tap":
		kind = "Tap"
	}

	return kind
}

func decodeNetDevJSONRequest(r *http.Request) (*NetDev, error) {
	n := NetDev{}
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		return nil, err
	}

	return &n, nil
}

func (n *NetDev) BuildNetDevSection(m *configfile.Meta) error {
	m.NewSection("NetDev")

	if !validator.IsEmpty(n.Description) {
		m.SetKeyToNewSectionString("Description", n.Description)
	}

	if validator.IsEmpty(n.Name) {
		log.Errorf("Failed to create VLan. Missing NetDev name")
		return errors.New("missing netdev name")

	}
	m.SetKeyToNewSectionString("Name", n.Name)

	if validator.IsEmpty(n.Kind) {
		log.Errorf("Failed to create VLan. Missing NetDev kind")
		return errors.New("missing netdev kind")
	}
	m.SetKeyToNewSectionString("Kind", n.Kind)

	if !validator.IsEmpty(n.MACAddress) {
		if validator.IsNotMAC(n.MACAddress) {
			log.Errorf("Failed to create VLan='%s'. Invalid MACAddress='%s': %v", n.Name, n.MTUBytes)
			return fmt.Errorf("invalid MACAddress='%s'", n.MACAddress)
		}

		m.SetKeyToNewSectionString("MACAddress", n.MACAddress)
	}

	if !validator.IsEmpty(n.MTUBytes) {
		if !validator.IsUint32(n.MTUBytes) {
			log.Errorf("Failed to create VLan='%s'. Invalid MTUBytes='%s': %v", n.Name, n.MTUBytes)
			return fmt.Errorf("invalid MTUBytes='%s'", n.MTUBytes)
		}

		m.SetKeyToNewSectionString("MTUBytes", n.MTUBytes)
	}

	return nil
}

func (n *NetDev) buildVlanSection(m *configfile.Meta) error {
	m.NewSection("VLAN")

	if n.VLanSection.Id == 0 {
		log.Errorf("Failed to create VLan='%s'. Missing Id,", n.Name)
		return errors.New("missing vlan id")
	}

	m.SetKeySectionUint("VLAN", "Id", n.VLanSection.Id)
	return nil
}

func (n *NetDev) buildBondSection(m *configfile.Meta) error {
	m.NewSection("Bond")

	// Mode Validate
	if !validator.IsEmpty(n.BondSection.Mode) {
		if !validator.IsBondMode(n.BondSection.Mode) {
			log.Errorf("Failed to create Bond='%s'. Invalid Mode='%s'", n.Name, n.BondSection.Mode)
			return fmt.Errorf("invalid mode='%s'", n.BondSection.Mode)
		}
		m.SetKeyToNewSectionString("Mode", n.BondSection.Mode)
	}
	// TransmitHashPolicy Validate
	if !validator.IsEmpty(n.BondSection.TransmitHashPolicy) {
		if !validator.IsBondTransmitHashPolicy(n.BondSection.Mode, n.BondSection.TransmitHashPolicy) {
			log.Errorf("Failed to create Bond='%s'. Invalid TransmitHashPolicy='%s' with mode='%s'", n.Name, n.BondSection.TransmitHashPolicy, n.BondSection.Mode)
			return fmt.Errorf("invalid transmithashpolicy='%s' with mode='%s'", n.BondSection.TransmitHashPolicy, n.BondSection.Mode)
		}
		m.SetKeyToNewSectionString("TransmitHashPolicy", n.BondSection.TransmitHashPolicy)
	}
	// LACPTransmitRate Validate
	if !validator.IsEmpty(n.BondSection.LACPTransmitRate) {
		if !validator.IsBondLACPTransmitRate(n.BondSection.LACPTransmitRate) {
			log.Errorf("Failed to create Bond='%s'. Invalid LACPTransmitRate='%s'", n.Name, n.BondSection.LACPTransmitRate)
			return fmt.Errorf("invalid lacptransmitRate='%s'", n.BondSection.LACPTransmitRate)
		}
		m.SetKeyToNewSectionString("LACPTransmitRate", n.BondSection.LACPTransmitRate)
	}
	// MIIMonitorSec Validate
	if !validator.IsEmpty(n.BondSection.MIIMonitorSec) {
		m.SetKeyToNewSectionString("MIIMonitorSec", n.BondSection.MIIMonitorSec)
	}

	return nil
}

func (n *NetDev) buildBridgeSection(m *configfile.Meta) error {
	m.NewSection("Bridge")

	if !validator.IsEmpty(n.BridgeSection.STP) {
		m.SetKeyToNewSectionString("STP", validator.BoolToString(n.BridgeSection.STP))
	}

	return nil
}

func (n *NetDev) buildMacVLanSection(m *configfile.Meta) error {
	m.NewSection("MACVLAN")

	// Mode Validate
	if validator.IsEmpty(n.MacVLanSection.Mode) {
		log.Errorf("Failed to create MacVLan='%s'. Missing Mode,", n.Name)
		return errors.New("missing macvlan mode")
	}
	if !validator.IsMacVLanMode(n.MacVLanSection.Mode) {
		log.Errorf("Failed to create MacVLan='%s'. Invalid Mode='%s'", n.Name, n.MacVLanSection.Mode)
		return fmt.Errorf("invalid mode='%s'", n.MacVLanSection.Mode)
	}
	m.SetKeyToNewSectionString("Mode", n.MacVLanSection.Mode)

	return nil
}

func (n *NetDev) buildMacVTapSection(m *configfile.Meta) error {
	m.NewSection("MACVTAP")

	// Mode Validate
	if validator.IsEmpty(n.MacVLanSection.Mode) {
		log.Errorf("Failed to create MacVTap='%s'. Missing Mode,", n.Name)
		return errors.New("missing macvlan mode")
	}
	if !validator.IsMacVLanMode(n.MacVLanSection.Mode) {
		log.Errorf("Failed to create MacVtap='%s'. Invalid Mode='%s'", n.Name, n.MacVLanSection.Mode)
		return fmt.Errorf("invalid mode='%s'", n.MacVLanSection.Mode)
	}
	m.SetKeyToNewSectionString("Mode", n.MacVLanSection.Mode)

	return nil
}

func (n *NetDev) buildIpVLanSection(m *configfile.Meta) error {
	m.NewSection("IPVLAN")

	// Mode Validate
	if !validator.IsEmpty(n.IpVLanSection.Mode) {
		if !validator.IsIpVLanMode(n.IpVLanSection.Mode) {
			log.Errorf("Failed to create IpVLan='%s'. Invalid Mode='%s'", n.Name, n.IpVLanSection.Mode)
			return fmt.Errorf("invalid mode='%s'", n.IpVLanSection.Mode)
		}
		m.SetKeyToNewSectionString("Mode", n.IpVLanSection.Mode)
	}
	// Flags Validate
	if !validator.IsEmpty(n.IpVLanSection.Flags) {
		if !validator.IsIpVLanFlags(n.IpVLanSection.Flags) {
			log.Errorf("Failed to create IpVLan='%s'. Invalid Flags='%s'", n.Name, n.IpVLanSection.Flags)
			return fmt.Errorf("invalid flags='%s'", n.IpVLanSection.Flags)
		}
		m.SetKeyToNewSectionString("Flags", n.IpVLanSection.Flags)
	}

	return nil
}

func (n *NetDev) buildVxLanSection(m *configfile.Meta) error {
	m.NewSection("VXLAN")

	// Mandatory Argument Check VNI
	if validator.IsEmpty(n.VxLanSection.VNI) {
		log.Errorf("Failed to create vxlan='%s'. Missing VNI", n.Name)
		return errors.New("missing vxlan vni")

	}
	if !validator.IsVxLanVNI(n.VxLanSection.VNI) {
		log.Errorf("Failed to create VxLan='%s'. Invalid VNI='%s'", n.Name, n.VxLanSection.VNI)
		return fmt.Errorf("invalid vni='%s'", n.VxLanSection.VNI)
	}
	m.SetKeyToNewSectionString("VNI", n.VxLanSection.VNI)

	if !validator.IsEmpty(n.VxLanSection.Remote) {
		if !validator.IsIP(n.VxLanSection.Remote) {
			log.Errorf("Failed to create VxLan='%s'. Invalid Remote='%s'", n.Name, n.VxLanSection.Remote)
			return fmt.Errorf("invalid remote='%s'", n.VxLanSection.Remote)
		}
		m.SetKeyToNewSectionString("Remote", n.VxLanSection.Remote)
	}

	if !validator.IsEmpty(n.VxLanSection.Local) {
		if !validator.IsIP(n.VxLanSection.Local) {
			log.Errorf("Failed to create VxLan='%s'. Invalid Local='%s'", n.Name, n.VxLanSection.Local)
			return fmt.Errorf("invalid local='%s'", n.VxLanSection.Local)
		}
		m.SetKeyToNewSectionString("Local", n.VxLanSection.Local)
	}

	if !validator.IsEmpty(n.VxLanSection.Group) {
		if !validator.IsIP(n.VxLanSection.Group) {
			log.Errorf("Failed to create VxLan='%s'. Invalid Group='%s'", n.Name, n.VxLanSection.Group)
			return fmt.Errorf("invalid Group='%s'", n.VxLanSection.Group)
		}
		m.SetKeyToNewSectionString("Group", n.VxLanSection.Group)
	}

	if !validator.IsEmpty(n.VxLanSection.DestinationPort) && validator.IsPort(n.VxLanSection.DestinationPort) {
		m.SetKeyToNewSectionString("DestinationPort", n.VxLanSection.DestinationPort)
	}

	if !validator.IsEmpty(n.VxLanSection.Independent) && validator.IsBool(n.VxLanSection.Independent) {
		m.SetKeyToNewSectionString("Independent", n.VxLanSection.Independent)
	}

	return nil
}

func (n *NetDev) buildWireGuardSection(m *configfile.Meta) error {
	m.NewSection("WireGuard")

	// Mandatory Argument Check
	if validator.IsEmpty(n.WireGuardSection.PrivateKey) && validator.IsEmpty(n.WireGuardSection.PrivateKeyFile) {
		log.Errorf("Failed to create WireGuard='%s'. Missing PrivateKey and PrivateKeyFile,", n.Name)
		return errors.New("missing wireguard privatekey and privatekeyfile")
	}

	// PrivateKey Validate
	if !validator.IsEmpty(n.WireGuardSection.PrivateKey) {
		m.SetKeyToNewSectionString("PrivateKey", n.WireGuardSection.PrivateKey)
	}
	// PrivateKeyFile Validate
	if !validator.IsEmpty(n.WireGuardSection.PrivateKeyFile) {
		m.SetKeyToNewSectionString("PrivateKeyFile", n.WireGuardSection.PrivateKeyFile)
	}
	// ListenPort Validate
	if !validator.IsEmpty(n.WireGuardSection.ListenPort) {
		if !validator.IsWireGuardListenPort(n.WireGuardSection.ListenPort) {
			log.Errorf("Failed to create WireGuard='%s'. Invalid ListenPort='%s'", n.Name, n.WireGuardSection.ListenPort)
			return fmt.Errorf("invalid listenport='%s'", n.WireGuardSection.ListenPort)
		}
		m.SetKeyToNewSectionString("ListenPort", n.WireGuardSection.ListenPort)
	}

	return nil
}

func (n *NetDev) buildWireGuardPeerSection(m *configfile.Meta) error {
	m.NewSection("WireGuardPeer")

	// PublicKey Validate
	if validator.IsEmpty(n.WireGuardPeerSection.PublicKey) {
		log.Errorf("Failed to create WireGuardPeer='%s'. Missing PublicKey,", n.Name)
		return errors.New("missing wireguardpeer publickey")
	}
	m.SetKeyToNewSectionString("PublicKey", n.WireGuardPeerSection.PublicKey)

	// Endpoint Validate
	if validator.IsEmpty(n.WireGuardPeerSection.Endpoint) {
		log.Errorf("Failed to create WireGuardPeer='%s'. Missing Endpoint,", n.Name)
		return errors.New("missing wireguardpeer endpoint")
	}

	if !validator.IsWireGuardPeerEndpoint(n.WireGuardPeerSection.Endpoint) {
		log.Errorf("Failed to create WireGuard='%s'. Invalid Endpoint='%s'", n.Name, n.WireGuardPeerSection.Endpoint)
		return fmt.Errorf("invalid endpoint='%s'", n.WireGuardPeerSection.Endpoint)
	}
	m.SetKeyToNewSectionString("Endpoint", n.WireGuardPeerSection.Endpoint)

	// PresharedKey Validate
	if !validator.IsEmpty(n.WireGuardPeerSection.PresharedKey) {
		m.SetKeyToNewSectionString("PresharedKey", n.WireGuardPeerSection.PresharedKey)
	}
	// PresharedKeyFile Validate
	if !validator.IsEmpty(n.WireGuardPeerSection.PresharedKeyFile) {
		m.SetKeyToNewSectionString("PresharedKeyFile", n.WireGuardPeerSection.PresharedKeyFile)
	}
	// AllowedIPs Validate
	if !validator.IsArrayEmpty(n.WireGuardPeerSection.AllowedIPs) {
		for _, ip := range n.WireGuardPeerSection.AllowedIPs {
			if !validator.IsIP(ip) {
				log.Errorf("Failed to create WireGuardPeer='%s'. Invalid AllowedIPs='%s'", n.Name, n.WireGuardPeerSection.AllowedIPs)
				return fmt.Errorf("invalid allowedips='%s'", n.WireGuardPeerSection.AllowedIPs)
			}
		}
		m.SetKeyToNewSectionString("AllowedIPs", strings.Join(n.WireGuardPeerSection.AllowedIPs, " "))
	}

	return nil
}

func (n *NetDev) buildTunOrTapSection(kind string, m *configfile.Meta) error {
	m.NewSection(netDevKindToNetworkKind(kind))

	if !validator.IsEmpty(n.TunOrTapSection.MultiQueue) {
		if !validator.IsBool(n.TunOrTapSection.MultiQueue) {
			log.Errorf("Failed to create %s='%s'. Invalid MultiQueue='%s'", kind, n.Name, n.TunOrTapSection.MultiQueue)
			return fmt.Errorf("invalid multiqueue='%s'", n.TunOrTapSection.MultiQueue)
		}
		m.SetKeyToNewSectionString("MultiQueue", validator.BoolToString(n.TunOrTapSection.MultiQueue))
	}

	if !validator.IsEmpty(n.TunOrTapSection.PacketInfo) {
		if !validator.IsBool(n.TunOrTapSection.PacketInfo) {
			log.Errorf("Failed to create %s='%s'. Invalid PacketInfo='%s'", kind, n.Name, n.TunOrTapSection.PacketInfo)
			return fmt.Errorf("invalid packetinfo='%s'", n.TunOrTapSection.PacketInfo)
		}
		m.SetKeyToNewSectionString("PacketInfo", validator.BoolToString(n.TunOrTapSection.PacketInfo))
	}

	if !validator.IsEmpty(n.TunOrTapSection.VNetHeader) {
		if !validator.IsBool(n.TunOrTapSection.VNetHeader) {
			log.Errorf("Failed to create %s='%s'. Invalid VNetHeader='%s'", kind, n.Name, n.TunOrTapSection.VNetHeader)
			return fmt.Errorf("invalid vnetheader='%s'", n.TunOrTapSection.VNetHeader)
		}
		m.SetKeyToNewSectionString("VNetHeader", validator.BoolToString(n.TunOrTapSection.VNetHeader))
	}

	if !validator.IsEmpty(n.TunOrTapSection.User) {
		m.SetKeyToNewSectionString("User", n.TunOrTapSection.User)
	}

	if !validator.IsEmpty(n.TunOrTapSection.Group) {
		m.SetKeyToNewSectionString("Group", n.TunOrTapSection.Group)
	}

	if !validator.IsEmpty(n.TunOrTapSection.KeepCarrier) {
		if !validator.IsBool(n.TunOrTapSection.KeepCarrier) {
			log.Errorf("Failed to create %s='%s'. Invalid KeepCarrier='%s'", kind, n.Name, n.TunOrTapSection.KeepCarrier)
			return fmt.Errorf("invalid keepcarrier='%s'", n.TunOrTapSection.KeepCarrier)
		}
		m.SetKeyToNewSectionString("KeepCarrier", validator.BoolToString(n.TunOrTapSection.KeepCarrier))
	}

	return nil
}

func (n *NetDev) BuildKindInLinkNetworkFile() error {
	for _, l := range n.Links {
		m, err := CreateOrParseNetworkFile(l)
		if err != nil {
			log.Errorf("Failed to parse network file for link='%s': %v", l, err)
			return fmt.Errorf("link='%s' %v", l, err.Error())
		}

		if err := m.NewKeyToSectionString("Network", netDevKindToNetworkKind(n.Kind), n.Name); err != nil {
			log.Errorf("Failed to update .network file of link='%s': %v", l, err)
			return err
		}

		if err := m.Save(); err != nil {
			log.Errorf("Failed to update config file='%s': %v", m.Path, err)
			return err
		}
	}

	return nil
}

func (n *NetDev) BuildKindSection(m *configfile.Meta) error {
	switch n.Kind {
	case "vlan":
		if err := n.buildVlanSection(m); err != nil {
			log.Errorf("Failed to create VLan ='%s': %v", n.Name, err)
			return err
		}
	case "bond":
		if err := n.buildBondSection(m); err != nil {
			log.Errorf("Failed to create Bond ='%s': %v", n.Name, err)
			return err
		}
	case "bridge":
		if err := n.buildBridgeSection(m); err != nil {
			log.Errorf("Failed to create Bridge ='%s': %v", n.Name, err)
			return err
		}
	case "macvlan":
		if err := n.buildMacVLanSection(m); err != nil {
			log.Errorf("Failed to create MacVLan ='%s': %v", n.Name, err)
			return err
		}
	case "macvtap":
		if err := n.buildMacVTapSection(m); err != nil {
			log.Errorf("Failed to create MacVTap ='%s': %v", n.Name, err)
			return err
		}
	case "ipvlan":
		if err := n.buildIpVLanSection(m); err != nil {
			log.Errorf("Failed to create IpVLan ='%s': %v", n.Name, err)
			return err
		}
	case "vxlan":
		if err := n.buildVxLanSection(m); err != nil {
			log.Errorf("Failed to create VxLan ='%s': %v", n.Name, err)
			return err
		}
	case "wireguard":
		if err := n.buildWireGuardSection(m); err != nil {
			log.Errorf("Failed to create WireGuard ='%s': %v", n.Name, err)
			return err
		}
		if err := n.buildWireGuardPeerSection(m); err != nil {
			log.Errorf("Failed to create WireGuardPeer ='%s': %v", n.Name, err)
			return err
		}
	case "tun", "tap":
		if err := n.buildTunOrTapSection(n.Kind, m); err != nil {
			log.Errorf("Failed to create %s ='%s': %v", n.Kind, n.Name, err)
			return err
		}
	}

	return nil
}

func (n *NetDev) ConfigureNetDev(ctx context.Context, w http.ResponseWriter) error {
	m, _, err := CreateOrParseNetDevFile(n.Name, n.Kind)
	if err != nil {
		log.Errorf("Failed to parse netdev file for link='%s': %v", n.Name, err)
		return err
	}

	if err = n.BuildNetDevSection(m); err != nil {
		return err
	}
	if err := n.BuildKindSection(m); err != nil {
		return err
	}
	if err := n.BuildKindInLinkNetworkFile(); err != nil {
		return err
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	// Create .network file for netdev
	if err := CreateNetDevNetworkFile(n.Name, n.Kind); err != nil {
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

func (n *NetDev) RemoveNetDev(ctx context.Context, w http.ResponseWriter) error {
	RemoveNetDev(n.Name, n.Kind)

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
