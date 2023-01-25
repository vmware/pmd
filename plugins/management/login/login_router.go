// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package login

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/web"
)

func routerAcquireUserList(w http.ResponseWriter, r *http.Request) {
	if err := AcquireUserListFromLogin(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireUser(w http.ResponseWriter, r *http.Request) {
	u, err := decodeUserJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := u.AcquireUserFromLogin(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireSessionList(w http.ResponseWriter, r *http.Request) {
	if err := AcquireSessionListFromLogin(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAcquireSession(w http.ResponseWriter, r *http.Request) {
	s, err := decodeSessionJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := s.AcquireSessionFromLogin(r.Context(), w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterLogin(router *mux.Router) {
	s := router.PathPrefix("/login").Subrouter().StrictSlash(false)

	s.HandleFunc("/listusers", routerAcquireUserList).Methods("GET")
	s.HandleFunc("/listsessions", routerAcquireSessionList).Methods("GET")
	s.HandleFunc("/getsession", routerAcquireSession).Methods("GET")
	s.HandleFunc("/getuser", routerAcquireUser).Methods("GET")
}
