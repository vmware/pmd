// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package firewall

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/vmware/pmd/pkg/web"
)

func routerAddTable(w http.ResponseWriter, r *http.Request) {
	t, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := t.AddTable(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerRemoveTable(w http.ResponseWriter, r *http.Request) {
	t, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := t.RemoveTable(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerShowTable(w http.ResponseWriter, r *http.Request) {
	t, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := t.ShowTable(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerAddChain(w http.ResponseWriter, r *http.Request) {
	c, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := c.AddChain(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerRemoveChain(w http.ResponseWriter, r *http.Request) {
	c, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := c.RemoveChain(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerShowChain(w http.ResponseWriter, r *http.Request) {
	c, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := c.ShowChain(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerSaveNFT(w http.ResponseWriter, r *http.Request) {
	t, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := t.SaveNFT(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func routerRunNFT(w http.ResponseWriter, r *http.Request) {
	t, err := decodeNftJSONRequest(r)
	if err != nil {
		http.Error(w, "Error decoding request", http.StatusBadRequest)
		return
	}

	if err := t.RunNFT(w); err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterNft(router *mux.Router) {
	n := router.PathPrefix("/firewall/nft/").Subrouter().StrictSlash(false)

	n.HandleFunc("/table/add", routerAddTable).Methods("POST")
	n.HandleFunc("/table/remove", routerRemoveTable).Methods("DELETE")
	n.HandleFunc("/table/show", routerShowTable).Methods("GET")
	n.HandleFunc("/chain/add", routerAddChain).Methods("POST")
	n.HandleFunc("/chain/remove", routerRemoveChain).Methods("DELETE")
	n.HandleFunc("/chain/show", routerShowChain).Methods("GET")
	n.HandleFunc("/save", routerSaveNFT).Methods("PUT")
	n.HandleFunc("/run", routerRunNFT).Methods("POST")
}
