// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package validator

import (
	"net"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/vishvananda/netlink"
)

func IsBool(str string) bool {
	switch str {
	case "1", "t", "T", "true", "TRUE", "True", "YES", "yes", "Yes", "y", "ON", "on", "On", "0", "f", "F",
		"false", "FALSE", "False", "NO", "no", "No", "n", "OFF", "off", "Off":
		return true
	}

	return false
}

func BoolToString(str string) string {
	switch str {
	case "1", "t", "T", "true", "TRUE", "True", "YES", "yes", "Yes", "y", "ON", "on", "On":
		return "yes"
	case "0", "f", "F", "false", "FALSE", "False", "NO", "no", "No", "n", "OFF", "off", "Off":
		return "no"
	}

	return "n/a"
}

func IsArrayEmpty(str []string) bool {
	return len(str) == 0
}

func IsEmpty(str string) bool {
	return govalidator.IsNull(str)
}

func IsUintOrMax(s string) bool {
	if strings.EqualFold(s, "max") {
		return true
	}

	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func IsUint32(s string) bool {
	_, err := strconv.ParseUint(s, 10, 32)
	return err == nil
}

func IsUint16(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}

func IsUint8(s string) bool {
	_, err := strconv.ParseUint(s, 10, 8)
	return err == nil
}

func IsInt(s string) (int, error) {
	v, err := strconv.Atoi(s)
	return v, err
}

func IsPort(port string) bool {
	_, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return false
	}

	return true
}

func IsHost(host string) bool {
	_, err := net.LookupHost(host)
	if err != nil {
		return false
	}

	return true
}

func IsValidIP(ip string) bool {
	a := net.ParseIP(ip)
	if a.To4() == nil && a.To16() == nil {
		return false
	}

	return true
}

func IsIP(str string) bool {
	_, _, err := net.ParseCIDR(str)
	if err != nil {
		ip := net.ParseIP(str)
		return ip != nil
	}

	return err == nil
}

func IsIPs(s []string) bool {
	for _, ip := range s {
		if !IsValidIP(ip) {
			return false
		}
	}

	return true
}

func IsVSockHost(host string) bool {
	h := strings.Split(host, ":")
	if len(h) < 2 {
		return false
	}

	return IsUint32(h[0]) && IsPort(h[1])

}

func IsDHCPDUIDType(id string) bool {
	return id == "vendor" || id == "uuid" || id == "link-layer-time" || id == "link-layer"
}

func IsDHCPOptionType(op string) bool {
	return op == "uint8" || op == "uint16" || op == "uint32" || op == "ipv4address" || op == "ipv6address" || op == "string"
}

func IsDHCPv4ClientIdentifier(identifier string) bool {
	return identifier == "mac" || identifier == "duid" || identifier == "duid-only"
}

func IsDHCPv4SendOption(option string) bool {
	vs := strings.Split(option, ",")
	if len(vs) < 3 {
		return false
	}

	return IsUint8(vs[0]) && IsDHCPOptionType(vs[1])

}

func IsDHCPv6WithoutRA(ra string) bool {
	return ra == "no" || ra == "solicit" || ra == "information-request"
}

func IsDHCPv6SendVendorOption(option string) bool {
	vs := strings.Split(option, ",")
	if len(vs) < 4 {
		return false
	}

	return IsUint32(vs[0]) && IsUint8(vs[1]) && IsDHCPOptionType(vs[2])
}

func IsNotMAC(mac string) bool {
	return !govalidator.IsMAC(mac)
}

func IsScope(s string) bool {
	switch s {
	case "global", "link", "host":
		return true
	}

	scope, err := strconv.ParseUint(s, 10, 32)
	if err != nil || scope >= 256 {
		return false
	}

	return true
}

func IsBoolWithIp(s string) bool {
	switch s {
	case "yes", "no", "ipv4", "ipv6":
		return true
	}

	return false
}

func IsDHCP(s string) bool {
	return IsBoolWithIp(s)
}

func IsLinkLocalAddressing(s string) bool {
	return IsBoolWithIp(s)
}

func IsMulticastDNS(s string) bool {
	return IsBool(s) || s == "resolve"
}

func IsBondMode(mode string) bool {
	return mode == "balance-rr" || mode == "active-backup" || mode == "balance-xor" ||
		mode == "broadcast" || mode == "802.3ad" || mode == "balance-tlb" || mode == "balance-alb"
}

func IsBondTransmitHashPolicy(mode, thp string) bool {
	if (thp == "layer2" || thp == "layer3+4" || thp == "layer2+3" || thp == "encap2+3" || thp == "encap3+4") &&
		(mode == "balance-xor" || mode == "802.3ad" || mode == "balance-tlb") {
		return true
	}

	return false
}

func IsBondLACPTransmitRate(ltr string) bool {
	return ltr == "slow" || ltr == "fast"
}

func IsMacVLanMode(mode string) bool {
	return mode == "private" || mode == "vepa" || mode == "bridge" || mode == "passthru" || mode == "source"
}

func IsIpVLanMode(mode string) bool {
	return mode == "l2" || mode == "l3" || mode == "l3s"
}

func IsIpVLanFlags(flags string) bool {
	return flags == "bridge" || flags == "private" || flags == "vepa"
}

func IsVxLanVNI(id string) bool {
	l, err := strconv.ParseUint(id, 10, 32)
	if err != nil || l > 16777215 {
		return false
	}

	return true
}

func IsWireGuardListenPort(port string) bool {
	return port == "auto" || IsPort(port)
}

func IsWireGuardPeerEndpoint(endPoint string) bool {
	ip, port, err := net.SplitHostPort(endPoint)
	if err != nil {
		return false
	}
	if !IsValidIP(ip) && !IsHost(ip) {
		return false
	}
	if !IsPort(port) {
		return false
	}

	return true
}

func IsLinkMACAddressPolicy(policy string) bool {
	return policy == "persistent" || policy == "random" || policy == "none"
}

func IsLinkNamePolicy(policy string) bool {
	return policy == "kernel" || policy == "database" || policy == "onboard" ||
		policy == "slot" || policy == "path" || policy == "mac" || policy == "keep"
}

func IsLinkName(name string) bool {
	if strings.HasPrefix(name, "eth") || strings.HasPrefix(name, "ens") || strings.HasPrefix(name, "lo") {
		return false
	}

	return true
}

func IsLinkAlternativeNamesPolicy(policy string) bool {
	return policy == "database" || policy == "onboard" || policy == "slot" ||
		policy == "path" || policy == "mac"
}

func IsLinkQueue(id string) bool {
	l, err := strconv.ParseUint(id, 10, 32)
	if err != nil || l > 4096 {
		return false
	}

	return true
}

func IsLinkQueueLength(queueLength string) bool {
	l, err := strconv.ParseUint(queueLength, 10, 32)
	if err != nil || l > 4294967294 {
		return false
	}

	return true
}

func IsLinkMtu(value string) bool {
	if strings.HasSuffix(value, "K") || strings.HasSuffix(value, "M") || strings.HasSuffix(value, "G") {
		return true
	}
	return IsUint32(value)
}

func IsLinkBitsPerSecond(value string) bool {
	if strings.HasSuffix(value, "K") || strings.HasSuffix(value, "M") || strings.HasSuffix(value, "G") {
		return true
	}
	return IsUint32(value)
}

func IsLinkDuplex(duplex string) bool {
	return duplex == "full" || duplex == "half"
}

func IsLinkWakeOnLan(value string) bool {
	return value == "off" || value == "phy" || value == "unicast" || value == "multicast" ||
		value == "broadcast" || value == "arp" || value == "magic" || value == "secureon"
}

func IsLinkPort(port string) bool {
	return port == "tp" || port == "aui" || port == "bnc" || port == "mii" || port == "fibre"
}

func IsLinkAdvertise(advertise string) bool {
	return advertise == "10baset-half" || advertise == "10baset-full" || advertise == "100baset-half" ||
		advertise == "100baset-full" || advertise == "1000baset-half" || advertise == "1000baset-full" ||
		advertise == "10000baset-full" || advertise == "2500basex-full" || advertise == "1000basekx-full" ||
		advertise == "10000basekx4-full" || advertise == "10000basekr-full" || advertise == "10000baser-fec" ||
		advertise == "20000basemld2-full" || advertise == "20000basekr2-full"
}

func IsLinkGSO(value string) bool {
	if strings.HasSuffix(value, "K") || strings.HasSuffix(value, "M") || strings.HasSuffix(value, "G") {
		return true
	}

	l, err := strconv.ParseUint(value, 10, 32)
	if err != nil || l > 65536 {
		return false
	}

	return true
}

func IsLinkGroup(value string) bool {
	l, err := strconv.ParseUint(value, 10, 32)
	if err != nil || l > 2147483647 {
		return false
	}

	return true
}

func IsAddressFamily(family string) bool {
	return family == "ipv4" || family == "ipv6" || family == "both" || family == "any"
}

func IsLinkActivationPolicy(policy string) bool {
	return policy == "up" || policy == "always-up" || policy == "down" ||
		policy == "always-down" || policy == "manual" || policy == "bound"
}

func LinkExists(link string) bool {
	_, err := netlink.LinkByName(link)
	return err == nil
}

func IsRoutingTypeOfService(svc string) bool {
	_, err := strconv.ParseUint(svc, 10, 8)
	if err != nil {
		return false
	}

	return true
}

func IsRoutingFirewallMark(mark string) bool {
	mrk := strings.Split(mark, "/")
	if len(mrk) > 2 {
		return false
	}

	for _, m := range mrk {
		if !IsUint32(m) {
			return false
		}
	}

	return true
}

func IsRoutingPort(port string) bool {
	prt := strings.Split(port, "-")
	if len(prt) > 2 {
		return false
	}

	for _, p := range prt {
		if !IsPort(p) {
			return false
		}
	}

	if len(prt) == 2 {
		if prt[0] > prt[1] {
			return false
		}
	}

	return true
}

func IsRoutingIPProtocol(p string) bool {
	return p == "tcp" || p == "udp" || p == "sctp" || p == "6" || p == "17"
}

func IsRoutingUser(usr string) bool {
	u := strings.Split(usr, "-")
	if len(u) > 2 {
		return false
	}

	for _, uu := range u {
		if !IsUint32(uu) {
			return false
		}
	}

	if len(u) == 2 {
		if u[0] > u[1] {
			return false
		}
	}

	return true
}

func IsRoutingSuppressPrefixLength(value string) bool {
	l, err := strconv.ParseUint(value, 10, 8)
	if err != nil || l > 128 {
		return false
	}

	return true
}

func IsRoutingType(typ string) bool {
	return typ == "blackhole" || typ == "unreachable" || typ == "prohibit"
}

func IsRouterPreference(p string) bool {
	return p == "high" || p == "low" || p == "medium" || p == "normal" || p == "default"
}

func IsNFTFamily(f string) bool {
	return f == "inet" || f == "ipv4" || f == "ipv6" || f == "netdev" || f == "bridge"
}

func IsNFTChainHook(h string) bool {
	return h == "prerouting" || h == "postrouting" || h == "ingress" || h == "input" || h == "forward" || h == "output"
}

func IsNFTChainType(c string) bool {
	return c == "filter" || c == "route" || c == "nat"
}

func IsNFTChainPolicy(p string) bool {
	return p == "drop" || p == "accept"
}

func IsProcSysNetPath(p string) bool {
	return p == "core" || p == "ipv4" || p == "ipv6"
}

// see https://fedoraproject.org/wiki/Packaging:Naming
func IsValidPkgName(name string) bool {
	if IsEmpty(name) {
		return false
	}
	for _, c := range name {
		if c >= 'A' && c <= 'Z' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' || c == '.' || c == '_' || c == '+' {
			continue
		}
		// allow globs
		if c == '*' || c == '?' {
			continue
		}
		return false
	}
	return true
}

// we allow multiple packages separated by commas
func IsValidPkgNameList(pkglist string) bool {
	for _, name := range strings.Split(pkglist, ",") {
		if !IsValidPkgName(name) {
			return false
		}
	}
	return true
}
