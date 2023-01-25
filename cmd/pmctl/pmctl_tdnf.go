// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"

	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/tdnf"
)

type ItemListDesc struct {
	Success bool            `json:"success"`
	Message []tdnf.ListItem `json:"message"`
	Errors  string          `json:"errors"`
}

type ItemSearchDesc struct {
	Success bool              `json:"success"`
	Message []tdnf.SearchItem `json:"message"`
	Errors  string            `json:"errors"`
}

type RepoListDesc struct {
	Success bool        `json:"success"`
	Message []tdnf.Repo `json:"message"`
	Errors  string      `json:"errors"`
}

type InfoListDesc struct {
	Success bool        `json:"success"`
	Message []tdnf.Info `json:"message"`
	Errors  string      `json:"errors"`
}

type RepoQueryResultDesc struct {
	Success bool                   `json:"success"`
	Message []tdnf.RepoQueryResult `json:"message"`
	Errors  string                 `json:"errors"`
}

type UpdateInfoDesc struct {
	Success bool              `json:"success"`
	Message []tdnf.UpdateInfo `json:"message"`
	Errors  string            `json:"errors"`
}

type UpdateInfoSummaryDesc struct {
	Success bool                   `json:"success"`
	Message tdnf.UpdateInfoSummary `json:"message"`
	Errors  string                 `json:"errors"`
}

type AlterResultDesc struct {
	Success bool             `json:"success"`
	Message tdnf.AlterResult `json:"message"`
	Errors  string           `json:"errors"`
}

type VersionDesc struct {
	Success bool         `json:"success"`
	Message tdnf.Version `json:"message"`
	Errors  string       `json:"errors"`
}

type NilDesc struct {
	Success bool   `json:"success"`
	Errors  string `json:"errors"`
}

type StatusDesc struct {
	Success bool               `json:"success"`
	Message web.StatusResponse `json:"message"`
	Errors  string             `json:"errors"`
}

type HistoryListDesc struct {
	Success bool                   `json:"success"`
	Message []tdnf.HistoryListItem `json:"message"`
	Errors  string                 `json:"errors"`
}

func tdnfParseFlagsInterface(c *cli.Context, optType reflect.Type) interface{} {
	options := reflect.New(optType)
	v := options.Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		name := strings.ToLower(field.Name)
		value := v.Field(i).Interface()
		switch value.(type) {
		case bool:
			v.Field(i).SetBool(c.Bool(name))
		case int:
			v.Field(i).SetInt(c.Int64(name))
		case string:
			v.Field(i).SetString(c.String(name))
		case []string:
			str := c.String(name)
			if !validator.IsEmpty(str) {
				list := strings.Split(str, ",")
				size := len(list)
				if size > 0 {
					v.Field(i).Set(reflect.MakeSlice(reflect.TypeOf([]string{}), size, size))
					for j, s := range list {
						v.Field(i).Index(j).Set(reflect.ValueOf(s))
					}
				}
			}
		}
	}
	return options.Interface()
}

func tdnfParseFlags(c *cli.Context) tdnf.Options {
	var o tdnf.Options
	o = *tdnfParseFlagsInterface(c, reflect.TypeOf(o)).(*tdnf.Options)
	return o
}

func tdnfParseScopeFlags(c *cli.Context) tdnf.ScopeOptions {
	var o tdnf.ScopeOptions
	o = *tdnfParseFlagsInterface(c, reflect.TypeOf(o)).(*tdnf.ScopeOptions)
	return o
}

func tdnfParseModeFlags(c *cli.Context) tdnf.ModeOptions {
	var o tdnf.ModeOptions
	o = *tdnfParseFlagsInterface(c, reflect.TypeOf(o)).(*tdnf.ModeOptions)
	return o
}

func tdnfParseQueryFlags(c *cli.Context) tdnf.QueryOptions {
	var o tdnf.QueryOptions
	o = *tdnfParseFlagsInterface(c, reflect.TypeOf(o)).(*tdnf.QueryOptions)
	return o
}

func tdnfParseListFlags(c *cli.Context) tdnf.ListOptions {
	return tdnf.ListOptions{
		tdnfParseFlags(c),
		tdnfParseScopeFlags(c),
	}
}

func tdnfParseRepoQueryFlags(c *cli.Context) tdnf.RepoQueryOptions {
	return tdnf.RepoQueryOptions{
		tdnfParseFlags(c),
		tdnfParseQueryFlags(c),
	}
}

func tdnfParseUpdateInfoFlags(c *cli.Context) tdnf.UpdateInfoOptions {
	return tdnf.UpdateInfoOptions{
		tdnfParseFlags(c),
		tdnfParseScopeFlags(c),
		tdnfParseModeFlags(c),
	}
}

func tdnfParseHistoryFlags(c *cli.Context) tdnf.HistoryOptions {
	var o tdnf.HistoryOptions
	o = *tdnfParseFlagsInterface(c, reflect.TypeOf(o)).(*tdnf.HistoryOptions)
	return o
}

func tdnfParseHistoryCmdFlags(c *cli.Context) tdnf.HistoryCmdOptions {
	return tdnf.HistoryCmdOptions{
		tdnfParseFlags(c),
		tdnfParseHistoryFlags(c),
	}
}

func tdnfCreateFlagsInterface(optType reflect.Type) []cli.Flag {
	var flags []cli.Flag

	options := reflect.New(optType)
	v := options.Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		name := strings.ToLower(field.Name)
		value := v.Field(i).Interface()
		switch value.(type) {
		case bool:
			flags = append(flags, &cli.BoolFlag{Name: name})
		case int:
			flags = append(flags, &cli.IntFlag{Name: name})
		case string:
			flags = append(flags, &cli.StringFlag{Name: name})
		case []string:
			flags = append(flags, &cli.StringFlag{Name: name, Usage: "Separate by ,"})
		}
	}
	return flags
}

func tdnfCreateFlags() []cli.Flag {
	var o tdnf.Options
	return tdnfCreateFlagsInterface(reflect.TypeOf(o))
}

func tdnfCreateScopeFlags() []cli.Flag {
	var o tdnf.ScopeOptions
	return tdnfCreateFlagsInterface(reflect.TypeOf(o))
}

func tdnfCreateQueryFlags() []cli.Flag {
	var o tdnf.QueryOptions
	return tdnfCreateFlagsInterface(reflect.TypeOf(o))
}

func tdnfCreateModeFlags() []cli.Flag {
	var o tdnf.ModeOptions
	return tdnfCreateFlagsInterface(reflect.TypeOf(o))
}

func tdnfCreateHistoryFlags() []cli.Flag {
	var o tdnf.HistoryOptions
	return tdnfCreateFlagsInterface(reflect.TypeOf(o))
}

func tdnfCreateAlterCommand(cmd string, aliases []string, desc string, pkgRequired bool, token map[string]string) *cli.Command {
	return &cli.Command{
		Name:        cmd,
		Aliases:     aliases,
		Description: desc,

		Action: func(c *cli.Context) error {
			options := tdnfParseFlags(c)
			if c.NArg() > 1 {
				fmt.Printf("Too many arguments\n")
				return nil
			} else if c.NArg() == 1 {
				pkgs := c.Args().First()
				if !validator.IsValidPkgNameList(pkgs) {
					fmt.Printf("Not a valid a package name or list\n")
					return nil
				}
				tdnfAlterCmd(&options, cmd, c.Args().First(), c.String("url"), token)
			} else {
				if pkgRequired {
					fmt.Printf("Needs a package name\n")
					return nil
				}
				tdnfAlterCmd(&options, cmd, "", c.String("url"), token)
			}
			return nil
		},
	}
}

func tdnfCreateHistoryAlterCommand(cmd string, aliases []string, desc string, token map[string]string) *cli.Command {
	return &cli.Command{
		Name:        cmd,
		Aliases:     aliases,
		Description: desc,
		Flags:       tdnfCreateHistoryFlags(),

		Action: func(c *cli.Context) error {
			options := tdnfParseHistoryCmdFlags(c)
			if c.NArg() >= 1 {
				fmt.Printf("Too many arguments\n")
				return nil
			} else {
				tdnfHistoryAlterCmd(&options, cmd, c.String("url"), token)
			}
			return nil
		},
	}
}

func tdnfOptionsMap(options interface{}) url.Values {
	m := url.Values{}

	v := reflect.ValueOf(options).Elem()
	for i := 0; i < v.NumField(); i++ {
		field := v.Type().Field(i)
		name := strings.ToLower(field.Name)
		switch v.Field(i).Kind() {
		case reflect.Struct:
			value := v.Field(i).Addr().Interface()
			m1 := tdnfOptionsMap(value)
			for k, v := range m1 {
				m[k] = v
			}
		default:
			value := v.Field(i).Interface()
			switch value.(type) {
			case bool:
				if value.(bool) {
					m.Add(name, "true")
				}
			case int:
				i := value.(int)
				m.Add(name, strconv.Itoa(i))
			case string:
				str := value.(string)
				if !validator.IsEmpty(str) {
					m.Add(name, str)
				}
			case []string:
				list := value.([]string)
				if len(list) != 0 {
					m[name] = list
				}
			}
		}
	}
	return m
}

func tdnfOptionsQuery(options interface{}) string {
	if m := tdnfOptionsMap(options); len(m) != 0 {
		return "?" + m.Encode()
	}
	return ""
}

func displayTdnfList(l *ItemListDesc) {
	for _, i := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("Name:"), i.Name)
		fmt.Printf("%v %v\n", color.HiBlueString("Arch:"), i.Arch)
		fmt.Printf("%v %v\n", color.HiBlueString(" Evr:"), i.Evr)
		fmt.Printf("%v %v\n", color.HiBlueString("Repo:"), i.Repo)
		fmt.Printf("\n")
	}
}

func displayTdnfSearch(l *ItemSearchDesc) {
	for _, i := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("   Name:"), i.Name)
		fmt.Printf("%v %v\n", color.HiBlueString("Summary:"), i.Summary)
		fmt.Printf("\n")
	}
}

func displayTdnfRepoList(l *RepoListDesc) {
	for _, r := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("   Repo:"), r.Repo)
		fmt.Printf("%v %v\n", color.HiBlueString("   Name:"), r.RepoName)
		fmt.Printf("%v %v\n", color.HiBlueString("Enabled:"), r.Enabled)
		fmt.Printf("\n")
	}
}

func displayTdnfInfoList(l *InfoListDesc) {
	for _, i := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("        Name:"), i.Name)
		fmt.Printf("%v %v\n", color.HiBlueString("        Arch:"), i.Arch)
		fmt.Printf("%v %v\n", color.HiBlueString("         Evr:"), i.Evr)
		fmt.Printf("%v %v\n", color.HiBlueString("Install Size:"), i.InstallSize)
		fmt.Printf("%v %v\n", color.HiBlueString("        Repo:"), i.Repo)
		fmt.Printf("%v %v\n", color.HiBlueString("     Summary:"), i.Summary)
		fmt.Printf("%v %v\n", color.HiBlueString("         Url:"), i.Url)
		fmt.Printf("%v %v\n", color.HiBlueString("     License:"), i.License)
		fmt.Printf("%v %v\n", color.HiBlueString(" Description:"), i.Description)
		fmt.Printf("\n")
	}
}

func displayTdnfRepoQueryResult(l *RepoQueryResultDesc) {
	displayList := func(label string, l []string) {
		if len(l) > 0 {
			fmt.Printf("%v %v\n", color.HiBlueString(label), strings.Join(l, ", "))
		}
	}

	for _, i := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("       Name:"), i.Name)
		fmt.Printf("%v %v\n", color.HiBlueString("       Arch:"), i.Arch)
		fmt.Printf("%v %v\n", color.HiBlueString("        Evr:"), i.Evr)
		fmt.Printf("%v %v\n", color.HiBlueString("       Repo:"), i.Repo)

		displayList("       Files:", i.Files)
		displayList("    Provides:", i.Provides)
		displayList("   Obsoletes:", i.Obsoletes)
		displayList("   Conflicts:", i.Conflicts)
		displayList("    Requires:", i.Requires)
		displayList("  Recommends:", i.Recommends)
		displayList("    Suggests:", i.Suggests)
		displayList(" Supplements:", i.Supplements)
		displayList("    Enhances:", i.Enhances)
		displayList("     Depends:", i.Depends)
		displayList("Requires-pre:", i.RequiresPre)

		if len(i.ChangeLogs) > 0 {
			fmt.Printf(color.HiBlueString(" ChangeLogs:\n"))
			for _, cl := range i.ChangeLogs {
				fmt.Printf("%v %v\n%v\n", cl.Time, cl.Author, cl.Text)
			}
		}
		if len(i.Source) > 0 {
			fmt.Printf("%v %v\n", color.HiBlueString("     Source:"), i.Source)
		}
		fmt.Printf("\n")
	}
}

func displayTdnfUpdateInfoSummary(s *UpdateInfoSummaryDesc) {
	m := s.Message
	fmt.Printf("%v %v\n", color.HiBlueString("   Security:"), m.Security)
	fmt.Printf("%v %v\n", color.HiBlueString("     Bugfix:"), m.Bugfix)
	fmt.Printf("%v %v\n", color.HiBlueString("Enhancement:"), m.Enhancement)
	fmt.Printf("%v %v\n", color.HiBlueString("    Unknown:"), m.Unknown)
}

func displayTdnfUpdateInfo(l *UpdateInfoDesc, options tdnf.ModeOptions) {
	for _, i := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("    UpdateID:"), i.UpdateId)
		fmt.Printf("%v %v\n", color.HiBlueString("        Type:"), i.Type)
		if options.Info {
			fmt.Printf("%v %v\n", color.HiBlueString("     Updated:"), i.Updated)
			fmt.Printf("%v %v\n", color.HiBlueString("Needs Reboot:"), i.NeedsReboot)
			fmt.Printf("%v %v\n", color.HiBlueString(" Description:"), i.Description)
		}
		fmt.Printf("%v %v\n", color.HiBlueString("    Packages:"), strings.Join(i.Packages, ", "))
		fmt.Printf("\n")
	}
}

func displayAlterList(l []tdnf.ListItem, header string) {
	if len(l) > 0 {
		fmt.Printf("%s:\n\n", header)
		for _, i := range l {
			fmt.Printf("%v %v\n", color.HiBlueString("Name:"), i.Name)
			fmt.Printf("%v %v\n", color.HiBlueString("Arch:"), i.Arch)
			fmt.Printf("%v %v\n", color.HiBlueString(" Evr:"), i.Evr)
			fmt.Printf("%v %v\n", color.HiBlueString("Repo:"), i.Repo)
			fmt.Printf("%v %v\n", color.HiBlueString("Size:"), i.Size)
			fmt.Printf("\n")
		}
	}
}

func displayTdnfAlterResult(rDesc *AlterResultDesc) {
	r := rDesc.Message
	displayAlterList(r.Exist, "Existing Packages")
	displayAlterList(r.Unavailable, "Unavailable Packages")
	displayAlterList(r.Install, "Packages to Install")
	displayAlterList(r.Upgrade, "Packages to Upgrade")
	displayAlterList(r.Downgrade, "Packages to Downgrade")
	displayAlterList(r.Remove, "Packages to Remove")
	displayAlterList(r.UnNeeded, "Unneeded Packages")
	displayAlterList(r.Reinstall, "Packages to Reinstall")
	displayAlterList(r.Obsolete, "Packages to be Obsoleted")
}

func displayTdnfHistoryListResult(l *HistoryListDesc) {
	displayList := func(label string, l []string) {
		if len(l) > 0 {
			fmt.Printf("%v %v\n", color.HiBlueString(label), strings.Join(l, ", "))
		}
	}

	for _, i := range l.Message {
		fmt.Printf("%v %v\n", color.HiBlueString("              Id:"), i.Id)
		fmt.Printf("%v %v\n", color.HiBlueString("    Command Line:"), i.CmdLine)
		fmt.Printf("%v %v\n", color.HiBlueString("  Added Packages:"), i.AddedCount)
		fmt.Printf("%v %v\n", color.HiBlueString("Removed Packages:"), i.RemovedCount)
		fmt.Printf("%v %v\n", color.HiBlueString("      Time Stamp:"), i.TimeStamp)

		displayList("           Added:", i.Added)
		displayList("         Removed:", i.Removed)
		fmt.Printf("\n")
	}
}

func acquireTdnfList(options *tdnf.ListOptions, pkg string, host string, token map[string]string) (*ItemListDesc, error) {
	var path string
	if !validator.IsEmpty(pkg) {
		path = "/api/v1/tdnf/list/" + pkg
	} else {
		path = "/api/v1/tdnf/list"
	}
	path = path + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := ItemListDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfRepoList(options *tdnf.Options, host string, token map[string]string) (*RepoListDesc, error) {
	resp, err := web.DispatchAndWait(http.MethodGet, host, "/api/v1/tdnf/repolist"+tdnfOptionsQuery(options), token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf repolist: %v\n", err)
		return nil, err
	}

	m := RepoListDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfInfoList(options *tdnf.ListOptions, pkg string, host string, token map[string]string) (*InfoListDesc, error) {
	var path string
	if !validator.IsEmpty(pkg) {
		path = "/api/v1/tdnf/info/" + pkg
	} else {
		path = "/api/v1/tdnf/info"
	}
	path = path + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := InfoListDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfRepoQuery(options *tdnf.RepoQueryOptions, pkg string, host string, token map[string]string) (*RepoQueryResultDesc, error) {
	var path string
	if !validator.IsEmpty(pkg) {
		path = "/api/v1/tdnf/repoquery/" + pkg
	} else {
		path = "/api/v1/tdnf/repoquery"
	}
	path = path + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := RepoQueryResultDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfUpdateInfo(options *tdnf.UpdateInfoOptions, pkg string, host string, token map[string]string) (*UpdateInfoDesc, error) {
	var path string
	if !validator.IsEmpty(pkg) {
		path = "/api/v1/tdnf/updateinfo/" + pkg
	} else {
		path = "/api/v1/tdnf/updateinfo"
	}
	path = path + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := UpdateInfoDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfUpdateInfoSummary(options *tdnf.UpdateInfoOptions, pkg string, host string, token map[string]string) (*UpdateInfoSummaryDesc, error) {
	var path string
	if !validator.IsEmpty(pkg) {
		path = "/api/v1/tdnf/updateinfo/" + pkg
	} else {
		path = "/api/v1/tdnf/updateinfo"
	}
	path = path + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := UpdateInfoSummaryDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfCheckUpdate(options *tdnf.Options, pkg string, host string, token map[string]string) (*ItemListDesc, error) {
	var path string
	if !validator.IsEmpty(pkg) {
		path = "/api/v1/tdnf/check-update/" + pkg
	} else {
		path = "/api/v1/tdnf/check-update"
	}
	path = path + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := ItemListDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfSearch(options *tdnf.Options, q string, host string, token map[string]string) (*ItemSearchDesc, error) {
	var path string

	v := tdnfOptionsMap(options)
	v.Add("q", q)
	path = "/api/v1/tdnf/search?" + v.Encode()

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := ItemSearchDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfSimpleCommand(options *tdnf.Options, cmd string, host string, token map[string]string) (*NilDesc, error) {
	var msg []byte

	msg, err := web.DispatchAndWait(http.MethodGet, host, "/api/v1/tdnf/"+cmd+tdnfOptionsQuery(options), token, nil)
	if err != nil {
		return nil, err
	}

	m := NilDesc{}
	if err := json.Unmarshal(msg, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfVersion(options *tdnf.Options, host string, token map[string]string) (*VersionDesc, error) {
	resp, err := web.DispatchAndWait(http.MethodGet, host, "/api/v1/tdnf/version"+tdnfOptionsQuery(options), token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf version: %v\n", err)
		return nil, err
	}

	m := VersionDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfAlterCmd(options *tdnf.Options, cmd string, pkgs string, host string, token map[string]string) (*AlterResultDesc, error) {
	var msg []byte
	var req string

	if pkgs != "" {
		req = "/api/v1/tdnf/" + cmd + "/" + pkgs + tdnfOptionsQuery(options)
	} else {
		req = "/api/v1/tdnf/" + cmd + tdnfOptionsQuery(options)
	}

	fmt.Printf("req: %s\n", req)
	msg, err := web.DispatchAndWait(http.MethodGet, host, req, token, nil)
	if err != nil {
		return nil, err
	}

	m := AlterResultDesc{}
	if err := json.Unmarshal(msg, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfHistoryList(options *tdnf.HistoryCmdOptions, host string, token map[string]string) (*HistoryListDesc, error) {
	var path string
	path = "/api/v1/tdnf/history/list" + tdnfOptionsQuery(options)

	resp, err := web.DispatchAndWait(http.MethodGet, host, path, token, nil)
	if err != nil {
		return nil, err
	}

	m := HistoryListDesc{}
	if err := json.Unmarshal(resp, &m); err != nil {
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func acquireTdnfHistoryAlterCmd(options *tdnf.HistoryCmdOptions, cmd string, host string, token map[string]string) (*AlterResultDesc, error) {
	var msg []byte

	msg, err := web.DispatchAndWait(http.MethodGet, host, "/api/v1/tdnf/history/"+cmd+tdnfOptionsQuery(options), token, nil)
	if err != nil {
		return nil, err
	}

	m := AlterResultDesc{}
	if err := json.Unmarshal(msg, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if m.Success {
		return &m, nil
	}

	return nil, errors.New(m.Errors)
}

func tdnfClean(options *tdnf.Options, host string, token map[string]string) {
	_, err := acquireTdnfSimpleCommand(options, "clean", host, token)
	if err != nil {
		fmt.Printf("Failed execute tdnf clean: %v\n", err)
		return
	}
	fmt.Printf("package cache cleaned\n")
}

func tdnfCheckUpdate(options *tdnf.Options, pkg string, host string, token map[string]string) {
	l, err := acquireTdnfCheckUpdate(options, pkg, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire check-update: %v\n", err)
		return
	}
	displayTdnfList(l)
}

func tdnfList(options *tdnf.ListOptions, pkg string, host string, token map[string]string) {
	l, err := acquireTdnfList(options, pkg, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf list: %v\n", err)
		return
	}
	displayTdnfList(l)
}

func tdnfMakeCache(options *tdnf.Options, host string, token map[string]string) {
	_, err := acquireTdnfSimpleCommand(options, "makecache", host, token)
	if err != nil {
		fmt.Printf("Failed tdnf makecache: %v\n", err)
		return
	}
	fmt.Printf("package cache acquired\n")
}

func tdnfRepoList(options *tdnf.Options, host string, token map[string]string) {
	l, err := acquireTdnfRepoList(options, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf repolist: %v\n", err)
		return
	}
	displayTdnfRepoList(l)
}

func tdnfSearch(options *tdnf.Options, pkg string, host string, token map[string]string) {
	l, err := acquireTdnfSearch(options, pkg, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf search: %v\n", err)
		return
	}
	displayTdnfSearch(l)
}

func tdnfInfoList(options *tdnf.ListOptions, pkg string, host string, token map[string]string) {
	l, err := acquireTdnfInfoList(options, pkg, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf info: %v\n", err)
		return
	}
	displayTdnfInfoList(l)
}

func tdnfRepoQuery(options *tdnf.RepoQueryOptions, pkg string, host string, token map[string]string) {
	l, err := acquireTdnfRepoQuery(options, pkg, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf repoquery: %v\n", err)
		return
	}
	displayTdnfRepoQueryResult(l)
}

func tdnfUpdateInfo(options *tdnf.UpdateInfoOptions, pkg string, host string, token map[string]string) {
	if options.List || options.Info {
		s, err := acquireTdnfUpdateInfo(options, pkg, host, token)
		if err != nil {
			fmt.Printf("Failed to acquire tdnf updateinfo: %v\n", err)
			return
		}
		displayTdnfUpdateInfo(s, options.ModeOptions)
	} else {
		s, err := acquireTdnfUpdateInfoSummary(options, pkg, host, token)
		if err != nil {
			fmt.Printf("Failed to acquire tdnf updateinfo: %v\n", err)
			return
		}
		displayTdnfUpdateInfoSummary(s)
	}
}

func tdnfAlterCmd(options *tdnf.Options, cmd string, pkg string, host string, token map[string]string) {
	l, err := acquireTdnfAlterCmd(options, cmd, pkg, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf %s: %v\n", cmd, err)
		return
	}
	displayTdnfAlterResult(l)
}

func tdnfHistoryInit(options *tdnf.Options, host string, token map[string]string) {
	_, err := acquireTdnfSimpleCommand(options, "history/init", host, token)
	if err != nil {
		fmt.Printf("Failed tdnf history init: %v\n", err)
		return
	}
	fmt.Printf("history db initialized\n")
}

func tdnfHistoryList(options *tdnf.HistoryCmdOptions, host string, token map[string]string) {
	l, err := acquireTdnfHistoryList(options, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf history list: %v\n", err)
		return
	}
	displayTdnfHistoryListResult(l)
}

func tdnfHistoryAlterCmd(options *tdnf.HistoryCmdOptions, cmd string, host string, token map[string]string) {
	l, err := acquireTdnfHistoryAlterCmd(options, cmd, host, token)
	if err != nil {
		fmt.Printf("Failed to acquire tdnf history %s: %v\n", cmd, err)
		return
	}
	displayTdnfAlterResult(l)
}

func tdnfMark(options *tdnf.Options, what string, pkgs string, host string, token map[string]string) {
	_, err := acquireTdnfSimpleCommand(options, "mark/"+what+"/"+pkgs, host, token)
	if err != nil {
		fmt.Printf("Failed tdnf mark: %v\n", err)
		return
	}
	fmt.Printf("%s marked\n", pkgs)
}
