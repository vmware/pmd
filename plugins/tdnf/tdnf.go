// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package tdnf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/jobs"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
)

type ListItem struct {
	Name string `json:"Name"`
	Arch string `json:"Arch"`
	Evr  string `json:"Evr"`
	Repo string `json:"Repo"`
	Size int    `json:"Size"`
}

type SearchItem struct {
	Name    string `json:"Name"`
	Summary string `json:"Summary"`
}

type Repo struct {
	Repo     string `json:"Repo"`
	RepoName string `json:"RepoName"`
	Enabled  bool   `json:"Enabled"`
}

type Info struct {
	Name        string `json:"Name"`
	Arch        string `json:"Arch"`
	Evr         string `json:"Evr"`
	InstallSize int    `json:"InstallSize"`
	Repo        string `json:"Repo"`
	Summary     string `json:"Summary"`
	Url         string `json:"Url"`
	License     string `json:"License"`
	Description string `json:"Description"`
}

type AlterResult struct {
	Exist       []ListItem
	Unavailable []ListItem
	Install     []ListItem
	Upgrade     []ListItem
	Downgrade   []ListItem
	Remove      []ListItem
	UnNeeded    []ListItem
	Reinstall   []ListItem
	Obsolete    []ListItem
}

type RepoQueryResult struct {
	Nevra       string
	Name        string
	Arch        string
	Evr         string
	Repo        string
	Files       []string
	Provides    []string
	Obsoletes   []string
	Conflicts   []string
	Requires    []string
	Recommends  []string
	Suggests    []string
	Supplements []string
	Enhances    []string
	Depends     []string
	RequiresPre []string
	ChangeLogs  []struct {
		Time   string
		Author string
		Text   string
	}
	Source string
}

type UpdateInfo struct {
	UpdateId    string
	Type        string
	Updated     string
	NeedsReboot bool
	Description string
	Packages    []string
}

type UpdateInfoSummary struct {
	Security    int
	Bugfix      int
	Enhancement int
	Unknown     int
}

type Version struct {
	Name    string
	Version string
}

type HistoryListItem struct {
	Id           int
	CmdLine      string
	TimeStamp    int
	AddedCount   int
	RemovedCount int
	Added        []string
	Removed      []string
}

type Options struct {
	AllowErasing    bool     `tdnf:"--allowerasing"`
	Best            bool     `tdnf:"--best"`
	CacheOnly       bool     `tdnf:"--cacheonly"`
	Config          string   `tdnf:"--config"`
	DisableRepo     []string `tdnf:"--disablerepo"`
	DisableExcludes bool     `tdnf:"--disableexcludes"`
	DownloadDir     string   `tdnf:"--downloaddir"`
	DownloadOnly    bool     `tdnf:"--downloadonly"`
	EnableRepo      []string `tdnf:"--enablerepo"`
	Exclude         string   `tdnf:"--exclude"`
	InstallRoot     string   `tdnf:"--installroot"`
	NoAutoRemove    bool     `tdnf:"--noautoremove"`
	NoGPGCheck      bool     `tdnf:"--nogpgcheck"`
	NoPlugins       bool     `tdnf:"--noplugins"`
	RebootRequired  bool     `tdnf:"--rebootrequired"`
	Refresh         bool     `tdnf:"--refresh"`
	ReleaseVer      string   `tdnf:"--releasever"`
	RepoId          string   `tdnf:"--repoid"`
	RepoFromPath    string   `tdnf:"--repofrompath"`
	Security        bool     `tdnf:"--security"`
	SecSeverity     string   `tdnf:"--sec-severity"`
	SetOpt          []string `tdnf:"--setopt"`
	SkipConflicts   bool     `tdnf:"--skipconflicts"`
	SkipDigest      bool     `tdnf:"--skipdigest"`
	SkipObsoletes   bool     `tdnf:"--skipobsoletes"`
	SkipSignature   bool     `tdnf:"--skipsignature"`
}

type ScopeOptions struct {
	Installed  bool `tdnf:"--installed"`
	Available  bool `tdnf:"--available"`
	Extras     bool `tdnf:"--extras"`
	Obsoletes  bool `tdnf:"--obsoletes"`
	Recent     bool `tdnf:"--recent"`
	Upgrades   bool `tdnf:"--upgrades"`
	Downgrades bool `tdnf:"--downgrades"`
}

type QueryOptions struct {
	Available       bool   `tdnf:"--available"`
	Duplicates      bool   `tdnf:"--duplicates"`
	Extras          bool   `tdnf:"--extras"`
	Installed       bool   `tdnf:"--installed"`
	Upgrades        bool   `tdnf:"--upgrades"`
	File            string `tdnf:"--file"`
	WhatProvides    string `tdnf:"--whatprovides"`
	WhatObsoletes   string `tdnf:"--whatobsoletes"`
	WhatConflicts   string `tdnf:"--whatconflicts"`
	WhatRequires    string `tdnf:"--whatrequires"`
	WhatRecommends  string `tdnf:"--whatrecommends"`
	WhatSuggests    string `tdnf:"--whatsuggests"`
	WhatSupplements string `tdnf:"--whatsupplements"`
	WhatEnhances    string `tdnf:"--whatenhances"`
	WhatDepends     string `tdnf:"--whatdepends"`

	ChangeLogs  bool `tdnf:"--changelogs"`
	List        bool `tdnf:"--list"`
	Source      bool `tdnf:"--source"`
	Provides    bool `tdnf:"--provides"`
	Obsoletes   bool `tdnf:"--obsoletes"`
	Conflicts   bool `tdnf:"--conflicts"`
	Requires    bool `tdnf:"--requires"`
	Recommends  bool `tdnf:"--recommends"`
	Suggests    bool `tdnf:"--suggests"`
	Supplements bool `tdnf:"--supplements"`
	Enhances    bool `tdnf:"--enhances"`
	Depends     bool `tdnf:"--depends"`
	RequiresPre bool `tdnf:"--requires-pre"`
}

type ModeOptions struct {
	Summary bool `tdnf:"--summary"`
	List    bool `tdnf:"--list"`
	Info    bool `tdnf:"--info"`
}

type ListOptions struct {
	Options
	ScopeOptions
}

type RepoQueryOptions struct {
	Options
	QueryOptions
}

type UpdateInfoOptions struct {
	Options
	ScopeOptions
	ModeOptions
}

type HistoryOptions struct {
	From    int  `tdnf:"--from"`
	To      int  `tdnf:"--to"`
	Info    bool `tdnf:"--info"`
	Reverse bool `tdnf:"--reverse"`
}

type HistoryCmdOptions struct {
	Options
	HistoryOptions
}

func TdnfOptions(options interface{}) []string {
	var strOptions []string

	v := reflect.ValueOf(options).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Struct:
			value := f.Addr().Interface()
			strOptions = append(strOptions, TdnfOptions(value)...)
		default:
			if opt := field.Tag.Get("tdnf"); opt != "" {
				value := f.Interface()
				switch value.(type) {
				case bool:
					if value.(bool) {
						strOptions = append(strOptions, opt)
					}
				case int:
					strOptions = append(strOptions, opt+"="+strconv.Itoa(value.(int)))
				case string:
					if strVal := value.(string); strVal != "" {
						strOptions = append(strOptions, opt+"="+strVal)
					}
				case []string:
					for _, s := range value.([]string) {
						strOptions = append(strOptions, opt+"="+s)
					}
				}
			}
		}
	}
	return strOptions
}

type ExecResult struct {
	Stdout bytes.Buffer
	Stderr bytes.Buffer
	Err    error
}

func execWithResult(cmd string, args ...string) *ExecResult {
	var result ExecResult

	c := exec.Command(cmd, args...)
	c.Stdout = &result.Stdout
	c.Stderr = &result.Stderr
	result.Err = c.Run()
	return &result
}

func TdnfExec(options interface{}, args ...string) (string, error) {
	args = append([]string{"-j"}, args...)

	if options != nil {
		args = append(TdnfOptions(options), args...)
	}
	fmt.Printf("calling tdnf %v\n", args)
	result := execWithResult("tdnf", args...)
	if result.Err != nil {
		return "", errors.Wrap(result.Err, result.Stderr.String())
	}
	return result.Stdout.String(), nil
}

func acquireCmdWithDelayedResponse(w http.ResponseWriter, cmd string, pkgs string, options interface{}) error {
	job := jobs.CreateJob(func() (interface{}, error) {
		var s string
		var err error
		if !validator.IsEmpty(pkgs) {
			s, err = TdnfExec(options, append([]string{cmd}, strings.Split(pkgs, ",")...)...)
		} else {
			s, err = TdnfExec(options, cmd)
		}
		var result interface{}
		if err := json.Unmarshal([]byte(s), &result); err != nil {
			return nil, err
		}
		return result, err
	})
	return jobs.AcceptedResponse(w, job)
}

func acquireCheckUpdate(w http.ResponseWriter, pkgs string, options Options) error {
	return acquireCmdWithDelayedResponse(w, "check-update", pkgs, &options)
}

func acquireList(w http.ResponseWriter, pkgs string, options ListOptions) error {
	return acquireCmdWithDelayedResponse(w, "list", pkgs, &options)
}

func acquireSearch(w http.ResponseWriter, pkgs string, options Options) error {
	return acquireCmdWithDelayedResponse(w, "search", pkgs, &options)
}

func acquireRepoList(w http.ResponseWriter, options Options) error {
	s, err := TdnfExec(&options, "repolist")
	if err != nil {
		log.Errorf("Failed to execute tdnf repolist: %v", err)
		return err
	}

	var repoList interface{}
	if err := json.Unmarshal([]byte(s), &repoList); err != nil {
		return err
	}
	return web.JSONResponse(repoList, w)
}

func acquireInfoList(w http.ResponseWriter, pkgs string, options ListOptions) error {
	return acquireCmdWithDelayedResponse(w, "info", pkgs, &options)
}

func acquireRepoQuery(w http.ResponseWriter, pkgs string, options RepoQueryOptions) error {
	return acquireCmdWithDelayedResponse(w, "repoquery", pkgs, &options)
}

func acquireMakeCache(w http.ResponseWriter, options Options) error {
	job := jobs.CreateJob(func() (interface{}, error) {
		_, err := TdnfExec(&options, "makecache")
		return nil, err
	})
	return jobs.AcceptedResponse(w, job)
}

func acquireClean(w http.ResponseWriter, options Options) error {
	_, err := TdnfExec(&options, "clean", "all")
	if err != nil {
		log.Errorf("Failed to execute tdnf clean all': %v", err)
		return err
	}
	return web.JSONResponse("cleaned", w)
}

func acquireAlterCmd(w http.ResponseWriter, cmd string, pkgs string, options Options) error {
	job := jobs.CreateJob(func() (interface{}, error) {
		var s string
		var err error
		if !validator.IsEmpty(pkgs) {
			s, err = TdnfExec(&options, append([]string{"-y", cmd}, strings.Split(pkgs, ",")...)...)
		} else {
			s, err = TdnfExec(&options, "-y", cmd)
		}
		if err != nil {
			return nil, err
		}
		var alterResult interface{}
		// An empty response indicates that nothing was to do
		if s != "" {
			if err := json.Unmarshal([]byte(s), &alterResult); err != nil {
				return nil, err
			}
		}
		return alterResult, err
	})
	return jobs.AcceptedResponse(w, job)
}

func acquireUpdateInfo(w http.ResponseWriter, pkgs string, options UpdateInfoOptions) error {
	return acquireCmdWithDelayedResponse(w, "updateinfo", pkgs, &options)
}

func acquireVersion(w http.ResponseWriter, options Options) error {
	s, err := TdnfExec(&options, "--version")
	if err != nil {
		log.Errorf("Failed to execute tdnf --version': %v", err)
		return err
	}
	var version interface{}
	if err := json.Unmarshal([]byte(s), &version); err != nil {
		return err
	}
	return web.JSONResponse(version, w)
}

func acquireHistoryList(w http.ResponseWriter, options HistoryCmdOptions) error {
	s, err := TdnfExec(&options, "history", "list")
	if err != nil {
		log.Errorf("Failed to execute tdnf history list': %v", err)
		return err
	}
	var historyList interface{}
	if err := json.Unmarshal([]byte(s), &historyList); err != nil {
		return err
	}
	return web.JSONResponse(historyList, w)
}

func acquireHistoryInit(w http.ResponseWriter, options HistoryCmdOptions) error {
	_, err := TdnfExec(&options, "history", "init")
	if err != nil {
		log.Errorf("Failed to execute tdnf history init': %v", err)
		return err
	}
	return web.JSONResponse("history initialized", w)
}

func acquireHistoryAlterCmd(w http.ResponseWriter, cmd string, options HistoryCmdOptions) error {
	job := jobs.CreateJob(func() (interface{}, error) {
		var s string
		var err error
		s, err = TdnfExec(&options, "-y", "history", cmd)
		if err != nil {
			return nil, err
		}
		var alterResult interface{}
		// An empty response indicates that nothing was to do
		if s != "" {
			if err := json.Unmarshal([]byte(s), &alterResult); err != nil {
				return nil, err
			}
		}
		return alterResult, err
	})
	return jobs.AcceptedResponse(w, job)
}

func acquireMarkCmd(w http.ResponseWriter, what string, pkgs string, options Options) error {
	job := jobs.CreateJob(func() (interface{}, error) {
		_, err := TdnfExec(&options, append([]string{"mark", what}, strings.Split(pkgs, ",")...)...)
		if err != nil {
			return nil, err
		}
		return nil, err
	})
	return jobs.AcceptedResponse(w, job)
}
