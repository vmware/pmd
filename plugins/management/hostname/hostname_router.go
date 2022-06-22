// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package hostname

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/web"
)

func routerHostnameDescribe(w http.ResponseWriter, r *http.Request) {
	desc, err := MethodDescribe(r.Context())
	if err != nil {
		web.JSONResponseError(err, w)
	}

	web.JSONResponse(desc, w)
}

func routerSetHostname(w http.ResponseWriter, r *http.Request) {
	hostname := Hostname{}
	if err := json.NewDecoder(r.Body).Decode(&hostname); err != nil {
		web.JSONResponseError(err, w)
		return
	}

	if err := hostname.Update(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterHostname(router *mux.Router) {
	s := router.PathPrefix("/hostname").Subrouter().StrictSlash(false)

	s.HandleFunc("/describe", routerHostnameDescribe).Methods("GET")
	s.HandleFunc("/update", routerSetHostname).Methods("POST")
}
