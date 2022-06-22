// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package resolved

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pmd-nextgen/pkg/web"
)

func routerAcquireLinkDns(w http.ResponseWriter, r *http.Request) {
	if err := AcquireLinkDns(r.Context(), mux.Vars(r)["link"], w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireLinkCurrentDns(w http.ResponseWriter, r *http.Request) {
	if err := AcquireLinkCurrentDns(r.Context(), mux.Vars(r)["link"], w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireLinkDomains(w http.ResponseWriter, r *http.Request) {
	if err := AcquireLinkDomains(r.Context(), mux.Vars(r)["link"], w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireDns(w http.ResponseWriter, r *http.Request) {
	dns, err := AcquireDns(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
	}

	web.JSONResponse(dns, w)
}

func routerAcquireDomains(w http.ResponseWriter, r *http.Request) {
	domains, err := AcquireDomains(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
	}

	web.JSONResponse(domains, w)
}

func routerDescribeDns(w http.ResponseWriter, r *http.Request) {
	d, err := DescribeDns(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
	}

	web.JSONResponse(d, w)
}

func routerAddDns(w http.ResponseWriter, r *http.Request) {
	d, err := decodeJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := d.AddDns(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerRemoveDns(w http.ResponseWriter, r *http.Request) {
	d, err := decodeJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := d.RemoveDns(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterResolved(router *mux.Router) {
	n := router.PathPrefix("/resolved").Subrouter().StrictSlash(false)

	n.HandleFunc("/describe", routerDescribeDns).Methods("GET")
	n.HandleFunc("/dns", routerAcquireDns).Methods("GET")
	n.HandleFunc("/domains", routerAcquireDomains).Methods("GET")
	n.HandleFunc("/{link}/dns", routerAcquireLinkDns).Methods("GET")
	n.HandleFunc("/{link}/domains", routerAcquireLinkDomains).Methods("GET")
	n.HandleFunc("/{link}/currentdns", routerAcquireLinkCurrentDns).Methods("GET")

	n.HandleFunc("/add", routerAddDns).Methods("POST")
	n.HandleFunc("/remove", routerRemoveDns).Methods("DELETE")
}
