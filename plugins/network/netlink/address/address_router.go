// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package address

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/web"
)

func routerAcquireAddress(w http.ResponseWriter, r *http.Request) {
	addrs, err := AcquireAddresses()
	if err != nil {
		web.JSONResponseError(err, w)
	}

	web.JSONResponse(addrs, w)
}

func RegisterRouterAddress(router *mux.Router) {
	s := router.PathPrefix("/netlink").Subrouter().StrictSlash(false)

	s.HandleFunc("/address", routerAcquireAddress).Methods("GET")
}
