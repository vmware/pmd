// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package user

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/web"
)

func routerAddUser(w http.ResponseWriter, r *http.Request) {
	u := User{}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := u.Add(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerModifyUser(w http.ResponseWriter, r *http.Request) {
	u := User{}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := u.Modify(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerRemoveUser(w http.ResponseWriter, r *http.Request) {
	u := User{}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := u.Remove(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerViewUsers(w http.ResponseWriter, r *http.Request) {
	u := User{}
	if err := u.View(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterUser(router *mux.Router) {
	s := router.PathPrefix("/user").Subrouter().StrictSlash(false)

	s.HandleFunc("/add", routerAddUser).Methods("POST")
	s.HandleFunc("/remove", routerRemoveUser).Methods("DELETE")
	s.HandleFunc("/modify", routerModifyUser).Methods("PUT")
	s.HandleFunc("/view", routerViewUsers).Methods("GET")
}
