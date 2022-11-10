// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package tdnf

import (
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
)

func routerParseOptionsInterface(values map[string][]string, optType reflect.Type) interface{} {

	isTrue := func(key string) bool {
		if v, ok := values[key]; ok {
			return validator.IsBool(v[0])
		}
		return false
	}

	getString := func(key string) string {
		if v, ok := values[key]; ok {
			return v[0]
		}
		return ""
	}

	getInt := func(key string) int {
		if v, ok := values[key]; ok {
			i, err := strconv.Atoi(v[0])
			if err == nil {
				return i
			}
		}
		return 0
	}

	options := reflect.New(optType)
	v := options.Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		name := strings.ToLower(field.Name)
		value := v.Field(i).Interface()
		switch value.(type) {
		case bool:
			v.Field(i).SetBool(isTrue(name))
		case int:
			v.Field(i).SetInt(int64(getInt(name)))
		case string:
			v.Field(i).SetString(getString(name))
		case []string:
			size := len(values[name])
			if size > 0 {
				v.Field(i).Set(reflect.MakeSlice(reflect.TypeOf([]string{}), size, size))
				for j, s := range values[name] {
					v.Field(i).Index(j).Set(reflect.ValueOf(s))
				}
			}
		}
	}
	return options.Interface()
}

func routerParseOptions(values map[string][]string) Options {
	var o Options
	o = *routerParseOptionsInterface(values, reflect.TypeOf(o)).(*Options)
	return o
}

func routerParseScopeOptions(values map[string][]string) ScopeOptions {
	var o ScopeOptions
	o = *routerParseOptionsInterface(values, reflect.TypeOf(o)).(*ScopeOptions)
	return o
}

func routerParseModeOptions(values map[string][]string) ModeOptions {
	var o ModeOptions
	o = *routerParseOptionsInterface(values, reflect.TypeOf(o)).(*ModeOptions)
	return o
}

func routerParseQueryOptions(values map[string][]string) QueryOptions {
	var o QueryOptions
	o = *routerParseOptionsInterface(values, reflect.TypeOf(o)).(*QueryOptions)
	return o
}

func routerParseHistoryOptions(values map[string][]string) HistoryOptions {
	var o HistoryOptions
	o = *routerParseOptionsInterface(values, reflect.TypeOf(o)).(*HistoryOptions)
	return o
}

func routeracquireCommand(w http.ResponseWriter, r *http.Request) {
	var err error

	if err = r.ParseForm(); err != nil {
		web.JSONResponseError(err, w)
	}
	options := routerParseOptions(r.Form)

	switch cmd := mux.Vars(r)["command"]; cmd {
	case "autoremove":
		err = acquireAlterCmd(w, cmd, "", options)
	case "check-update":
		err = acquireCheckUpdate(w, "", options)
	case "clean":
		err = acquireClean(w, options)
	case "distro-sync":
		err = acquireAlterCmd(w, cmd, "", options)
	case "downgrade":
		err = acquireAlterCmd(w, cmd, "", options)
	case "info":
		listOptions := ListOptions{options, routerParseScopeOptions(r.Form)}
		err = acquireInfoList(w, "", listOptions)
	case "list":
		listOptions := ListOptions{options, routerParseScopeOptions(r.Form)}
		err = acquireList(w, "", listOptions)
	case "makecache":
		err = acquireMakeCache(w, options)
	case "repolist":
		err = acquireRepoList(w, options)
	case "repoquery":
		repoQueryOptions := RepoQueryOptions{options, routerParseQueryOptions(r.Form)}
		err = acquireRepoQuery(w, "", repoQueryOptions)
	case "search":
		q := r.FormValue("q")
		if q != "" {
			err = acquireSearch(w, q, options)
		} else {
			err = errors.New("search needs 'q=str' query")
		}
	case "update":
		err = acquireAlterCmd(w, cmd, "", options)
	case "updateinfo":
		updateInfoOptions := UpdateInfoOptions{options, routerParseScopeOptions(r.Form), routerParseModeOptions(r.Form)}
		err = acquireUpdateInfo(w, "", updateInfoOptions)
	case "version":
		err = acquireVersion(w, options)
	default:
		err = errors.New("unsupported")
	}

	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func routeracquireCommandPkgs(w http.ResponseWriter, r *http.Request) {
	var err error

	pkgs := mux.Vars(r)["pkgs"]

	if err = r.ParseForm(); err != nil {
		web.JSONResponseError(err, w)
	}
	options := routerParseOptions(r.Form)

	switch cmd := mux.Vars(r)["command"]; cmd {
	case "autoremove":
		err = acquireAlterCmd(w, cmd, pkgs, options)
	case "downgrade":
		err = acquireAlterCmd(w, cmd, pkgs, options)
	case "check-update":
		err = acquireCheckUpdate(w, pkgs, options)
	case "erase":
		err = acquireAlterCmd(w, cmd, pkgs, options)
	case "info":
		listOptions := ListOptions{options, routerParseScopeOptions(r.Form)}
		err = acquireInfoList(w, pkgs, listOptions)
	case "install":
		err = acquireAlterCmd(w, cmd, pkgs, options)
	case "list":
		listOptions := ListOptions{options, routerParseScopeOptions(r.Form)}
		err = acquireList(w, pkgs, listOptions)
	case "reinstall":
		err = acquireAlterCmd(w, cmd, pkgs, options)
	case "repoquery":
		repoQueryOptions := RepoQueryOptions{options, routerParseQueryOptions(r.Form)}
		err = acquireRepoQuery(w, pkgs, repoQueryOptions)
	case "update":
		err = acquireAlterCmd(w, cmd, pkgs, options)
	case "updateinfo":
		updateInfoOptions := UpdateInfoOptions{options, routerParseScopeOptions(r.Form), routerParseModeOptions(r.Form)}
		err = acquireUpdateInfo(w, pkgs, updateInfoOptions)
	default:
		err = errors.New("unsupported")
	}

	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func routeracquireHistoryCommand(w http.ResponseWriter, r *http.Request) {
	var err error

	if err = r.ParseForm(); err != nil {
		web.JSONResponseError(err, w)
	}
	options := routerParseOptions(r.Form)
	historyCmdOptions := HistoryCmdOptions{options, routerParseHistoryOptions(r.Form)}

	switch cmd := mux.Vars(r)["command"]; cmd {
	case "init":
		err = acquireHistoryInit(w, historyCmdOptions)
	case "list":
		err = acquireHistoryList(w, historyCmdOptions)
	case "rollback":
		err = acquireHistoryAlterCmd(w, cmd, historyCmdOptions)
	case "undo":
		err = acquireHistoryAlterCmd(w, cmd, historyCmdOptions)
	case "redo":
		err = acquireHistoryAlterCmd(w, cmd, historyCmdOptions)
	default:
		err = errors.New("unsupported")
	}

	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func routeracquireMarkCommand(w http.ResponseWriter, r *http.Request) {
	var err error

	pkgs := mux.Vars(r)["pkgs"]
	if err = r.ParseForm(); err != nil {
		web.JSONResponseError(err, w)
	}
	options := routerParseOptions(r.Form)

	switch what := mux.Vars(r)["what"]; what {
	case "install":
		err = acquireMarkCmd(w, what, pkgs, options)
	case "remove":
		err = acquireMarkCmd(w, what, pkgs, options)
	default:
		err = errors.New("unsupported")
	}

	if err != nil {
		web.JSONResponseError(err, w)
	}
}

func RegisterRouterTdnf(router *mux.Router) {
	nh := router.PathPrefix("/tdnf/history").Subrouter().StrictSlash(false)
	nh.HandleFunc("/{command}", routeracquireHistoryCommand).Methods("GET")

	nm := router.PathPrefix("/tdnf/mark").Subrouter().StrictSlash(false)
	nm.HandleFunc("/{what}/{pkgs}", routeracquireMarkCommand).Methods("GET")

	n := router.PathPrefix("/tdnf").Subrouter().StrictSlash(false)
	n.HandleFunc("/{command}/{pkgs}", routeracquireCommandPkgs).Methods("GET")
	n.HandleFunc("/{command}", routeracquireCommand).Methods("GET")
}
