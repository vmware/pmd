// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package route

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/pmd-nextgen/pkg/parser"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Route struct {
	Action  string `json:"action"`
	Link    string `json:"link"`
	Gateway string `json:"gateway"`
	OnLink  string `json:"onlink"`
}

type RouteInfo struct {
	LinkName   string `json:"LinkName"`
	LinkIndex  int    `json:"LinkIndex"`
	ILinkIndex int    `json:"ILinkIndex"`
	Scope      int    `json:"Scope"`
	Dst        struct {
		IP   string `json:"IP"`
		Mask int    `json:"Mask"`
	} `json:"Dst"`
	Src       string   `json:"Src"`
	Gw        string   `json:"Gw"`
	MultiPath string   `json:"MultiPath"`
	Protocol  int      `json:"Protocol"`
	Priority  int      `json:"Priority"`
	Table     int      `json:"Table"`
	Type      int      `json:"Type"`
	Tos       int      `json:"Tos"`
	Flags     []string `json:"Flags"`
	MPLSDst   string   `json:"MPLSDst"`
	NewDst    string   `json:"NewDst"`
	Encap     string   `json:"Encap"`
	Mtu       int      `json:"MTU"`
	AdvMSS    int      `json:"AdvMSS"`
	Hoplimit  int      `json:"Hoplimit"`
}

func decodeJSONRequest(r *http.Request) (*Route, error) {
	rt := Route{}
	err := json.NewDecoder(r.Body).Decode(&rt)
	if err != nil {
		return nil, err
	}

	return &rt, nil
}

func (rt *Route) AddDefaultGateWay() error {
	link, err := netlink.LinkByName(rt.Link)
	if err != nil {
		log.Errorf("Failed to find link %s: %v", err, rt.Link)
		return err
	}

	ipAddr, _, err := net.ParseCIDR(rt.Gateway)
	if err != nil {
		log.Errorf("Failed to parse default GateWay address %s: %v", rt.Gateway, err)
		return err
	}

	onlink := 0
	b, err := parser.ParseBool(strings.TrimSpace(rt.OnLink))
	if err != nil {
		log.Errorf("Failed to parse GatewayOnlink='%s': %v", rt.OnLink, err)
	} else {
		if b {
			onlink |= syscall.RTNH_F_ONLINK
		}
	}

	route := &netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: link.Attrs().Index,
		Gw:        ipAddr,
		Flags:     onlink,
	}

	if err := netlink.RouteAdd(route); err != nil {
		log.Errorf("Failed to add default GateWay address %s: %v", rt.Gateway, err)
		return err
	}

	return nil
}

func (rt *Route) ReplaceDefaultGateWay() error {
	link, err := netlink.LinkByName(rt.Link)
	if err != nil {
		return err
	}

	ipAddr, _, err := net.ParseCIDR(rt.Gateway)
	if err != nil {
		log.Errorf("Failed to parse default GateWay='%s': %v", rt.Gateway, err)
		return err
	}

	onlink := 0
	b, err := parser.ParseBool(strings.TrimSpace(rt.OnLink))
	if err != nil {
		log.Errorf("Failed to parse GatewayOnlink='%s': %v", rt.OnLink, err)
	} else {
		if b {
			onlink |= syscall.RTNH_F_ONLINK
		}
	}

	route := &netlink.Route{
		Scope:     netlink.SCOPE_LINK,
		LinkIndex: link.Attrs().Index,
		Gw:        ipAddr,
		Flags:     onlink,
	}

	if err := netlink.RouteReplace(route); err != nil {
		log.Errorf("Failed to replace default GateWay='%s': %v", rt.Gateway, err)
		return err
	}

	return nil
}

func (rt *Route) RemoveGateWay() error {
	link, err := netlink.LinkByName(rt.Link)
	if err != nil {
		log.Errorf("Failed to delete default gateway='%s': %v", link, err)
		return err
	}

	ipAddr, _, err := net.ParseCIDR(rt.Gateway)
	if err != nil {
		return err
	}

	switch rt.Action {
	case "remove-default-gw":
		rt := &netlink.Route{
			Scope:     netlink.SCOPE_LINK,
			LinkIndex: link.Attrs().Index,
			Gw:        ipAddr,
		}

		if err = netlink.RouteDel(rt); err != nil {
			log.Errorf("Failed to delete default GateWay='%s': %v", ipAddr, err)
			return err
		}
	}

	return nil
}

func fillOneRoute(rt *netlink.Route) *RouteInfo {
	link, err := netlink.LinkByIndex(rt.LinkIndex)
	if err != nil {
		log.Debugf("Failed to acquire link ifindex='%d': %v", rt.LinkIndex, err)
		return nil
	}

	route := RouteInfo{
		LinkName:   link.Attrs().Name,
		LinkIndex:  rt.LinkIndex,
		ILinkIndex: rt.ILinkIndex,
		Scope:      int(rt.Scope),
		Protocol:   rt.Protocol,
		Priority:   rt.Priority,
		Table:      rt.Table,
		Type:       rt.Type,
		Tos:        rt.Tos,
		Mtu:        rt.MTU,
		AdvMSS:     rt.AdvMSS,
		Hoplimit:   rt.Hoplimit,
	}

	if rt.Gw != nil {
		route.Gw = rt.Gw.String()
	}

	if rt.Src != nil {
		route.Src = rt.Src.String()
	}

	if rt.Dst != nil {
		route.Dst.IP = rt.Dst.IP.String()
		route.Dst.Mask, _ = rt.Dst.Mask.Size()
	}

	if rt.Flags != 0 {
		route.Flags = rt.ListFlags()
	}

	return &route
}

func buildRouteList(routes []netlink.Route) []RouteInfo {
	var rts []RouteInfo
	for _, rt := range routes {
		if rt.LinkIndex == 0 {
			continue
		}

		route := fillOneRoute(&rt)
		if route != nil {
			rts = append(rts, *route)
		}
	}

	return rts
}

func AcquireRoutes() ([]RouteInfo, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, err
	}

	return buildRouteList(routes), nil
}

func (rt *Route) Configure() error {
	switch rt.Action {
	case "add-default-gw":
		return rt.AddDefaultGateWay()
	case "replace-default-gw":
		return rt.ReplaceDefaultGateWay()
	}

	return nil
}
