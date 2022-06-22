// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/user"
	"testing"

	"github.com/fatih/color"
	"github.com/pmd-nextgen/pkg/web"
	"github.com/pmd-nextgen/plugins/management/group"
	usr "github.com/pmd-nextgen/plugins/management/user"
)

func TestUserAdd(t *testing.T) {
	u := usr.User{
		Name:          "testusr",
		Gid:           "1002",
		Groups:        []string{"testusr", "nts"},
		HomeDirectory: "home/testusr",
		Comment:       "Test User",
		Shell:         "/bin/bash",
		Password:      "testpass",
	}

	resp, err := web.DispatchSocket(http.MethodPost, "", "/api/v1/system/user/add", nil, u)
	if err != nil {
		t.Fatalf("Failed to add user: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to add user: %v\n", m.Errors)
	}

	if _, err := user.Lookup(u.Name); err != nil {
		t.Fatalf("Failed to add user: %v\n", m.Errors)
	}
}

func TestAcquireUserStatus(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/user/view", nil, nil)
	if err != nil {
		t.Fatalf("Failed to fetch user status: %v\n", err)
	}

	u := UserStats{}
	if err := json.Unmarshal(resp, &u); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if u.Success {
		for _, usr := range u.Message {
			fmt.Printf("          %v %v\n", color.HiBlueString("User Name:"), usr.Name)
			fmt.Printf("                %v %v\n", color.HiBlueString("Uid:"), usr.Uid)
			fmt.Printf("                %v %v\n", color.HiBlueString("Gid:"), usr.Gid)
			if usr.Comment != "" {
				fmt.Printf("              %v %v\n", color.HiBlueString("GECOS:"), usr.Comment)
			}
			fmt.Printf("     %v %v\n\n", color.HiBlueString("Home Directory:"), usr.HomeDirectory)
		}
	} else {
		t.Fatalf(u.Errors)
	}
}

func TestUserRemove(t *testing.T) {
	u := usr.User{
		Name: "testusr",
	}

	resp, err := web.DispatchSocket(http.MethodDelete, "", "/api/v1/system/user/remove", nil, u)
	if err != nil {
		t.Fatalf("Failed to remove user: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to remove user: %v\n", m.Errors)
	}

	if _, err := user.Lookup(u.Name); err == nil {
		t.Fatalf("Failed to remove user: %v\n", m.Errors)
	}
}

func TestGroupAdd(t *testing.T) {
	g := group.Group{
		Name: "testgrp",
		Gid:  "1005",
	}

	resp, err := web.DispatchSocket(http.MethodPost, "", "/api/v1/system/group/add", nil, g)
	if err != nil {
		t.Fatalf("Failed to add group: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to add group: %v\n", m.Errors)
	}

	if _, err := user.LookupGroup(g.Name); err != nil {
		t.Fatalf("Failed to add group: %v\n", m.Errors)
	}
}

func TestAcquireGroupStatus(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/group/view", nil, nil)
	if err != nil {
		t.Fatalf("Failed to fetch group status: %v\n", err)
	}

	g := GroupStats{}
	if err := json.Unmarshal(resp, &g); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if g.Success {
		for _, grp := range g.Message {
			fmt.Printf("             %v %v\n", color.HiBlueString("Gid:"), grp.Gid)
			fmt.Printf("            %v %v\n\n", color.HiBlueString("Name:"), grp.Name)
		}
	} else {
		t.Fatalf(g.Errors)
	}
}

func TestGroupRemove(t *testing.T) {
	g := group.Group{
		Name: "testgrp",
	}

	resp, err := web.DispatchSocket(http.MethodDelete, "", "/api/v1/system/group/remove", nil, g)
	if err != nil {
		t.Fatalf("Failed to remove group: %v\n", err)
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if !m.Success {
		t.Fatalf("Failed to remove group: %v\n", m.Errors)
	}

	if _, err := user.LookupGroup(g.Name); err == nil {
		t.Fatalf("Failed to remove group: %v\n", m.Errors)
	}
}
