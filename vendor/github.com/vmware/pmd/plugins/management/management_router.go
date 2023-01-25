// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package management

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"

	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/management/group"
	"github.com/vmware/pmd/plugins/management/hostname"
	"github.com/vmware/pmd/plugins/management/login"
	"github.com/vmware/pmd/plugins/management/sysctl"
	"github.com/vmware/pmd/plugins/management/timedate"
	"github.com/vmware/pmd/plugins/management/user"
	"github.com/vmware/pmd/plugins/network/netlink/address"
	"github.com/vmware/pmd/plugins/network/netlink/route"
	"github.com/vmware/pmd/plugins/network/networkd"
	"github.com/vmware/pmd/plugins/systemd"
)

type Describe struct {
	Hostname          *hostname.Describe        `json:"Hostname"`
	Systemd           *systemd.Describe         `json:"Systemd"`
	TimeDate          *timedate.Describe        `json:"TimeDate"`
	NetworkDescribe   *networkd.NetworkDescribe `json:"NetworDescribe"`
	LinksDescribe     *networkd.LinksDescribe   `json:"LinksDescribe"`
	Addresses         []address.AddressInfo     `json:"Addresses"`
	Routes            []route.RouteInfo         `json:"Routes"`
	HostInfo          *host.InfoStat            `json:"HostInfo"`
	UserStat          []host.UserStat           `json:"UserStat"`
	VirtualMemoryStat *mem.VirtualMemoryStat    `json:"VirtualMemoryStat"`
}

func routerDescribeSystem(w http.ResponseWriter, r *http.Request) {
	var err error
	s := Describe{}

	s.Hostname, err = hostname.MethodDescribe(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.Systemd, err = systemd.ManagerDescribe(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.TimeDate, err = timedate.DBusAcquireTimeDate()
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.NetworkDescribe, err = networkd.AcquireNetworkState(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.LinksDescribe, err = networkd.AcquireLinks(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.Addresses, err = address.AcquireAddresses()
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.Routes, err = route.AcquireRoutes()
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.HostInfo, err = host.Info()
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.UserStat, err = host.Users()
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	s.VirtualMemoryStat, err = mem.VirtualMemoryWithContext(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	web.JSONResponse(s, w)
}

func RegisterRouterManagement(router *mux.Router) {
	n := router.PathPrefix("/system").Subrouter()

	group.RegisterRouterGroup(n)
	user.RegisterRouterUser(n)

	hostname.RegisterRouterHostname(n)
	login.RegisterRouterLogin(n)
	timedate.RegisterRouterTimeDate(n)

	sysctl.RegisterRouterSysctl(n)

	n.HandleFunc("/describe", routerDescribeSystem).Methods("GET")
}
