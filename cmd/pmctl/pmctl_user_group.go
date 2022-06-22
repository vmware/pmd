// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/pmd-nextgen/pkg/validator"
	"github.com/pmd-nextgen/pkg/web"
	"github.com/pmd-nextgen/plugins/management/group"
	"github.com/pmd-nextgen/plugins/management/user"
)

type GroupStats struct {
	Success bool          `json:"success"`
	Message []group.Group `json:"message"`
	Errors  string        `json:"errors"`
}

type UserStats struct {
	Success bool        `json:"success"`
	Message []user.User `json:"message"`
	Errors  string      `json:"errors"`
}

func acquireGroupStatus(groupName string, host string, token map[string]string) {
	url := "/api/v1/system/group/view"

	if !validator.IsEmpty(groupName) {
		url = url + "/" + groupName
	}

	resp, err := web.DispatchSocket(http.MethodGet, host, url, token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire group info: %v\n", err)
		return
	}

	g := GroupStats{}
	if err := json.Unmarshal(resp, &g); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !g.Success {
		fmt.Printf("Failed to fetch group status: %v\n", g.Errors)
		return
	}

	for _, grp := range g.Message {
		fmt.Printf("             %v %v\n", color.HiBlueString("Gid:"), grp.Gid)
		fmt.Printf("            %v %v\n\n", color.HiBlueString("Name:"), grp.Name)
	}
}

func groupAdd(name string, gid string, host string, token map[string]string) {
	g := group.Group{
		Name: name,
		Gid:  gid,
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/system/group/add", token, g)
	if err != nil {
		fmt.Printf("Failed add group: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if !m.Success {
		fmt.Printf("Failed to add group: %v\n", m.Errors)
		os.Exit(1)
	}

	fmt.Println(m.Message)
}

func groupRemove(name string, gid string, host string, token map[string]string) {
	g := group.Group{
		Name: name,
		Gid:  gid,
	}

	resp, err := web.DispatchSocket(http.MethodDelete, host, "/api/v1/system/group/remove", token, g)
	if err != nil {
		fmt.Printf("Failed remove group: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if !m.Success {
		fmt.Printf("Failed to remove group: %v\n", m.Errors)
		os.Exit(1)
	}

	fmt.Println(m.Message)
}

func userAdd(name string, uid string, groups string, gid string, shell string, homeDir string, password, string, host string, token map[string]string) {
	u := user.User{
		Name:          name,
		Uid:           uid,
		Gid:           gid,
		Shell:         shell,
		HomeDirectory: homeDir,
		Password:      password,
	}

	if !validator.IsEmpty(groups) {
		u.Groups = strings.Split(groups, ",")
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/system/user/add", token, u)
	if err != nil {
		fmt.Printf("Failed to add user: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if !m.Success {
		fmt.Printf("Failed to add user: %v\n", m.Errors)
		os.Exit(1)
	}

	fmt.Println(m.Message)
}

func userRemove(name string, host string, token map[string]string) {
	u := user.User{
		Name: name,
	}

	resp, err := web.DispatchSocket(http.MethodDelete, host, "/api/v1/system/user/remove", token, u)
	if err != nil {
		fmt.Printf("Failed remove user: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		os.Exit(1)
	}

	if !m.Success {
		fmt.Printf("Failed to remove user: %v\n", m.Errors)
		os.Exit(1)
	}

	fmt.Println(m.Message)
}

func acquireUserStatus(host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/system/user/view", token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire user info: %v\n", err)
		return
	}

	u := UserStats{}
	if err := json.Unmarshal(resp, &u); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !u.Success {
		fmt.Printf("Failed to acquire user info: %v\n", err)
		return
	}

	for _, usr := range u.Message {
		fmt.Printf("          %v %v\n", color.HiBlueString("User Name:"), usr.Name)
		fmt.Printf("                %v %v\n", color.HiBlueString("Uid:"), usr.Uid)
		fmt.Printf("                %v %v\n", color.HiBlueString("Gid:"), usr.Gid)
		if usr.Comment != "" {
			fmt.Printf("              %v %v\n", color.HiBlueString("GECOS:"), usr.Comment)
		}
		fmt.Printf("     %v %v\n\n", color.HiBlueString("Home Directory:"), usr.HomeDirectory)
	}
}
