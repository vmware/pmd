// SPDX-License-Identifier: Apache-2.0

package hello

import (
	"net/http"

	"github.com/gorilla/mux"
)

func routerSayHello(w http.ResponseWriter, r *http.Request) {
	g := new(Hello)

	vars := mux.Vars(r)
	text := vars["text"]

	g.Text = text

	err := g.SayHello(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// RegisterRouterSayHello register with mux
func RegisterRouterSayHello(router *mux.Router) {
	s := router.PathPrefix("/hello").Subrouter().StrictSlash(false)

	s.HandleFunc("/sayhello/{text}", routerSayHello).Methods("GET")
}
