// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package sysctl

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vmware/pmd/pkg/web"
)

func routerAcquireSysctl(w http.ResponseWriter, r *http.Request) {
	s := Sysctl{}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := s.Acquire(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireSysctlPattern(w http.ResponseWriter, r *http.Request) {
	s := Sysctl{}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := s.GetPattern(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireSysctlAll(w http.ResponseWriter, r *http.Request) {
	s := Sysctl{
		Pattern: "",
	}

	if err := s.GetPattern(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerUpdateSysctl(w http.ResponseWriter, r *http.Request) {
	s := Sysctl{}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := s.Update(w); err != nil {
		web.JSONResponseError(err, w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func routerRemoveSysctl(w http.ResponseWriter, r *http.Request) {
	s := Sysctl{}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	s.Value = "Delete"
	if err := s.Update(w); err != nil {
		web.JSONResponseError(err, w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func routerSysctlLoad(w http.ResponseWriter, r *http.Request) {
	s := new(Sysctl)
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := s.Load(w); err != nil {
		web.JSONResponseError(err, w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// RegisterRouterSysctl register with mux
func RegisterRouterSysctl(router *mux.Router) {
	s := router.PathPrefix("/sysctl").Subrouter().StrictSlash(false)

	s.HandleFunc("/status", routerAcquireSysctl).Methods("GET")
	s.HandleFunc("/statusall", routerAcquireSysctlAll).Methods("GET")
	s.HandleFunc("/statuspattern", routerAcquireSysctlPattern).Methods("GET")
	s.HandleFunc("/update", routerUpdateSysctl).Methods("POST")
	s.HandleFunc("/remove", routerRemoveSysctl).Methods("DELETE")
	s.HandleFunc("/load", routerSysctlLoad).Methods("POST")
}
