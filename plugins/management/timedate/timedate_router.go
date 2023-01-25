// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package timedate

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vmware/pmd/pkg/web"
)

func routerAcquireTimeDate(w http.ResponseWriter, r *http.Request) {
	if err := AcquireTimeDate(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerSetTimeDate(w http.ResponseWriter, r *http.Request) {
	t := TimeDate{}
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := t.ConfigureTimeDate(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterTimeDate(router *mux.Router) {
	t := router.PathPrefix("/timedate").Subrouter().StrictSlash(false)

	t.HandleFunc("/describe", routerAcquireTimeDate).Methods("GET")
	t.HandleFunc("/configure", routerSetTimeDate).Methods("POST")
}
