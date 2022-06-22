// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package timesyncd

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/web"
)

func routerAcquireNTPServers(w http.ResponseWriter, r *http.Request) {
	ntp, err := AcquireNTPServer(mux.Vars(r)["ntpserver"], r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	web.JSONResponse(ntp, w)
}

func routerDescribeNTPServers(w http.ResponseWriter, r *http.Request) {
	ntp, err := DescribeNTPServers(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	web.JSONResponse(ntp, w)
}

func routerAddNTP(w http.ResponseWriter, r *http.Request) {
	d, err := decodeJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := d.AddNTP(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerRemoveNTP(w http.ResponseWriter, r *http.Request) {
	d, err := decodeJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := d.RemoveNTP(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterTimeSyncd(router *mux.Router) {
	n := router.PathPrefix("/timesyncd").Subrouter().StrictSlash(false)

	n.HandleFunc("/describe", routerDescribeNTPServers).Methods("GET")
	n.HandleFunc("/{ntpserver}", routerAcquireNTPServers).Methods("GET")

	n.HandleFunc("/add", routerAddNTP).Methods("POST")
	n.HandleFunc("/remove", routerRemoveNTP).Methods("DELETE")
}
