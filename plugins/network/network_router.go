// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package network

import (
	"net/http"

	"github.com/gorilla/mux"

	log "github.com/sirupsen/logrus"

	"github.com/pmd-nextgen/pkg/web"
	"github.com/pmd-nextgen/plugins/network/ethtool"
	"github.com/pmd-nextgen/plugins/network/firewall"
	"github.com/pmd-nextgen/plugins/network/netlink/address"
	"github.com/pmd-nextgen/plugins/network/netlink/link"
	"github.com/pmd-nextgen/plugins/network/netlink/route"
	"github.com/pmd-nextgen/plugins/network/networkd"
	"github.com/pmd-nextgen/plugins/network/resolved"
	"github.com/pmd-nextgen/plugins/network/timesyncd"
)

type Describe struct {
	NetworkDescribe *networkd.NetworkDescribe `json:"NetworDescribe"`
	LinksDescribe   *networkd.LinksDescribe   `json:"LinksDescribe"`
	Links           []link.LinkInfo           `json:"links"`
	Addresses       []address.AddressInfo     `json:"Addresses"`
	Routes          []route.RouteInfo         `json:"Routes"`
	Dns             []resolved.Dns            `json:"Dns"`
	Domains         []resolved.Domains        `json:"Domains"`
}

func routerDescribeNetwork(w http.ResponseWriter, r *http.Request) {
	var err error
	n := Describe{}

	n.NetworkDescribe, err = networkd.AcquireNetworkState(r.Context())
	if err != nil {
		log.Errorf("Failed to acquire network state from systemd-networkd: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	n.LinksDescribe, err = networkd.AcquireLinks(r.Context())
	if err != nil {
		log.Errorf("Failed to acquire link state from systemd-networkd: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	n.Addresses, err = address.AcquireAddresses()
	if err != nil {
		log.Errorf("Failed to acquire addresses: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	n.Routes, err = route.AcquireRoutes()
	if err != nil {
		log.Errorf("Failed to acquire routes: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	n.Links, err = link.AcquireLinks()
	if err != nil {
		log.Errorf("Failed to acquire links: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	n.Dns, err = resolved.AcquireDns(r.Context())
	if err != nil {
		log.Errorf("Failed to acquire dDNS from systemd-resolved: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	n.Domains, err = resolved.AcquireDomains(r.Context())
	if err != nil {
		log.Errorf("Failed to acquire domains from systemd-resolved: %v", err)
		web.JSONResponseError(err, w)
		return
	}

	web.JSONResponse(n, w)
}

func RegisterRouterNetwork(router *mux.Router) {
	n := router.PathPrefix("/network").Subrouter()

	// netlink
	link.RegisterRouterLink(n)
	address.RegisterRouterAddress(n)
	route.RegisterRouterRoute(n)

	// ethtool
	ethtool.RegisterRouterEthTool(n)

	// systemd-networkd
	networkd.RegisterRouterNetworkd(n)
	// systemd-resolved
	resolved.RegisterRouterResolved(n)
	// systemd-timesynd
	timesyncd.RegisterRouterTimeSyncd(n)
	// firewall
	firewall.RegisterRouterNft(n)

	n.HandleFunc("/describe", routerDescribeNetwork).Methods("GET")
}
