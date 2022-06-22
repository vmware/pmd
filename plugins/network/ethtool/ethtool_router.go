// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package ethtool

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vmware/pmd/pkg/web"
)

func routerAcquirEthTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	e := Ethtool{
		Link: vars["link"],
	}

	err := e.AcquireEthTool(w)
	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquirActionEthTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	e := Ethtool{
		Link:   vars["link"],
		Action: vars["property"],
	}

	err := e.AcquireActionEthTool(w)
	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerConfigureEthTool(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	e := Ethtool{
		Link:   vars["link"],
		Action: vars["command"],
	}

	err := json.NewDecoder(r.Body).Decode(&e)
	if err != nil {
		web.JSONResponseError(err, w)
		return
	}

	err = e.ConfigureEthTool(w)
	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterEthTool(n *mux.Router) {
	e := n.PathPrefix("/ethtool").Subrouter().StrictSlash(false)

	e.HandleFunc("/{link}", routerAcquirEthTool).Methods("GET")
	e.HandleFunc("/{link}/{property}", routerAcquirActionEthTool).Methods("GET")
	e.HandleFunc("/{link}/{command}", routerConfigureEthTool).Methods("POST")
}
