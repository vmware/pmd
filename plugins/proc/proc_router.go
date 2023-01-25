// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package proc

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/web"
)

type Proc struct {
	Path     string `json:"path"`
	Property string `json:"property"`
	Value    string `json:"value"`
}

func routerAcquireProcNetStat(w http.ResponseWriter, r *http.Request) {
	if err := AcquireNetStat(w, mux.Vars(r)["protocol"]); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireProcPidNetStat(w http.ResponseWriter, r *http.Request) {
	if err := AcquireNetStatPid(w, mux.Vars(r)["protocol"], mux.Vars(r)["pid"]); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireProcSysVM(w http.ResponseWriter, r *http.Request) {
	vm := VM{
		Property: mux.Vars(r)["property"],
	}

	if err := vm.GetVM(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerConfigureProcSysVM(w http.ResponseWriter, r *http.Request) {
	vm := VM{
		Property: mux.Vars(r)["property"],
	}

	v := Proc{}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		web.JSONResponseError(err, w)
		return
	}

	vm.Value = v.Value
	if err := vm.SetVM(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireProcSysNet(w http.ResponseWriter, r *http.Request) {
	proc := SysNet{
		Path:     mux.Vars(r)["path"],
		Property: mux.Vars(r)["property"],
		Link:     mux.Vars(r)["link"],
	}

	if err := proc.GetSysNet(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func configureProcSysNet(w http.ResponseWriter, r *http.Request) {
	proc := SysNet{
		Path:     mux.Vars(r)["path"],
		Property: mux.Vars(r)["property"],
		Link:     mux.Vars(r)["link"],
	}

	v := Proc{}
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		web.JSONResponseError(err, w)
		return
	}

	proc.Value = v.Value
	if err := proc.SetSysNet(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireProcNetArp(w http.ResponseWriter, r *http.Request) {
	if err := AcquireNetArp(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireProcProcess(w http.ResponseWriter, r *http.Request) {
	if err := AcquireProcessInfo(w, mux.Vars(r)["pid"], mux.Vars(r)["property"]); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireSystem(w http.ResponseWriter, r *http.Request) {
	var err error

	switch mux.Vars(r)["system"] {
	case "avgstat":
		err = AcquireAvgStat(w)
	case "cpuinfo":
		err = AcquireCPUInfo(w)
	case "cputimestat":
		err = AcquireCPUTimeStat(w)
	case "diskusage":
		err = AcquireDiskUsage(w)
	case "iocounters":
		err = AcquireIOCounters(w)
	case "partitions":
		err = AcquirePartitions(w)
	case "temperaturestat":
		err = AcquireTemperatureStat(w)
	case "modules":
		err = AcquireModules(w)
	case "misc":
		err = AcquireMisc(w)
	case "userstat":
		err = AcquireUserStat(w)
	case "hostinfo":
		err = AcquireHostInfo(w)
	case "virtualmemory":
		err = AcquireVirtualMemoryStat(r.Context(), w)
	case "virtualization":
		err = AcquireVirtualization(w)
	case "platform":
		err = AcquirePlatformInformation(w)
	case "interfaces":
		err = AcquireInterfaces(w)
	case "netdeviocounters":
		err = AcquireNetDevIOCounters(w)
	case "protocounterstat":
		err = AcquireProtoCountersStat(w)
	default:
		err = errors.New("not found")
	}

	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterProc(router *mux.Router) {
	n := router.PathPrefix("/proc").Subrouter().StrictSlash(false)

	n.HandleFunc("/sys/net/{path}/{property}", routerAcquireProcSysNet).Methods("GET")
	n.HandleFunc("/sys/net/{path}/{link}/{property}", routerAcquireProcSysNet).Methods("GET")
	n.HandleFunc("/sys/net/{path}/{property}", configureProcSysNet).Methods("PUT")
	n.HandleFunc("/sys/net/{path}/{link}/{property}", configureProcSysNet).Methods("PUT")

	n.HandleFunc("/sys/vm/{property}", routerAcquireProcSysVM).Methods("GET")
	n.HandleFunc("/sys/vm/{property}", routerConfigureProcSysVM).Methods("PUT")

	n.HandleFunc("/{system}", routerAcquireSystem).Methods("GET")

	n.HandleFunc("/net/arp", routerAcquireProcNetArp).Methods("GET")
	n.HandleFunc("/netstat/{protocol}", routerAcquireProcNetStat).Methods("GET")

	n.HandleFunc("/process/{pid}/{property}", routerAcquireProcProcess).Methods("GET")
	n.HandleFunc("/protopidstat/{pid}/{protocol}", routerAcquireProcPidNetStat).Methods("GET")
}
