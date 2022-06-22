// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package group

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/pmd-nextgen/pkg/web"
)

func routerGroupAdd(w http.ResponseWriter, r *http.Request) {
	g := Group{}
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := g.GroupAdd(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerGroupModify(w http.ResponseWriter, r *http.Request) {
	g := Group{}
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := g.GroupModify(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerGroupRemove(w http.ResponseWriter, r *http.Request) {
	g := Group{}
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := g.GroupRemove(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerGroupView(w http.ResponseWriter, r *http.Request) {
	g := Group{
		Name: mux.Vars(r)["groupname"],
	}

	if err := g.GroupView(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterGroup(router *mux.Router) {
	s := router.PathPrefix("/group").Subrouter().StrictSlash(false)

	s.HandleFunc("/add", routerGroupAdd).Methods("POST")
	s.HandleFunc("/remove", routerGroupRemove).Methods("DELETE")
	s.HandleFunc("/modify", routerGroupModify).Methods("PUT")
	s.HandleFunc("/view", routerGroupView).Methods("GET")
	s.HandleFunc("/view/{groupname}", routerGroupView).Methods("GET")
}
