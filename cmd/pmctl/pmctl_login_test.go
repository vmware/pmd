// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/fatih/color"
	"github.com/pmd-nextgen/pkg/web"
)

func TestAcquireLoginUserStatus(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/login/listusers", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire login user info: %v\n", err)
	}

	u := LoginUserStats{}
	if err := json.Unmarshal(resp, &u); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if u.Success {
		for _, usr := range u.Message {
			fmt.Printf("           %v %v\n", color.HiBlueString("Uid:"), usr.UID)
			fmt.Printf("          %v %v\n", color.HiBlueString("Name:"), usr.Name)
			fmt.Printf("          %v %v\n\n", color.HiBlueString("Path:"), usr.Path)
		}

	} else {
		t.Fatalf(u.Errors)
	}
}

func TestAcquireLoginSessionStatus(t *testing.T) {
	resp, err := web.DispatchSocket(http.MethodGet, "", "/api/v1/system/login/listsessions", nil, nil)
	if err != nil {
		t.Fatalf("Failed to acquire login session info: %v\n", err)
	}

	s := LoginSessionStats{}
	if err := json.Unmarshal(resp, &s); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}

	if s.Success {
		for _, session := range s.Message {
			fmt.Printf("            %v %v\n", color.HiBlueString("Id:"), session.ID)
			fmt.Printf("           %v %v\n", color.HiBlueString("Uid:"), session.UID)
			fmt.Printf("          %v %v\n", color.HiBlueString("User:"), session.User)
			fmt.Printf("          %v %v\n", color.HiBlueString("Seat:"), session.Seat)
			fmt.Printf("          %v %v\n\n", color.HiBlueString("Path:"), session.Path)
		}
	} else {
		t.Fatalf(s.Errors)
	}
}
