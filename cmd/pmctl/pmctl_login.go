// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/fatih/color"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/management/login"
)

type LoginStats struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Errors  string `json:"errors"`
}

type LoginSessionStats struct {
	Success bool            `json:"success"`
	Message []login.Session `json:"message"`
	Errors  string          `json:"errors"`
}

type LoginUserStats struct {
	Success bool         `json:"success"`
	Message []login.User `json:"message"`
	Errors  string       `json:"errors"`
}

func acquireLoginUserListStatus(host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/system/login/listusers", token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire login user info: %v\n", err)
		return
	}

	u := LoginUserStats{}
	if err := json.Unmarshal(resp, &u); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !u.Success {
		fmt.Printf("Failed to acquire login user info: %v\n", u.Errors)
		return
	}

	for _, usr := range u.Message {
		fmt.Printf("           %v %v\n", color.HiBlueString("Uid:"), usr.UID)
		fmt.Printf("          %v %v\n", color.HiBlueString("Name:"), usr.Name)
		fmt.Printf("          %v %v\n\n", color.HiBlueString("Path:"), usr.Path)
	}
}

func acquireLoginSessionListStatus(host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/system/login/listsessions", token, nil)
	if err != nil {
		fmt.Printf("Failed to acquire login session info: %v\n", err)
		return
	}

	s := LoginSessionStats{}
	if err := json.Unmarshal(resp, &s); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !s.Success {
		fmt.Printf("Failed to acquire login session info: %v\n", s.Errors)
		return
	}

	for _, session := range s.Message {
		fmt.Printf("            %v %v\n", color.HiBlueString("Id:"), session.ID)
		fmt.Printf("           %v %v\n", color.HiBlueString("Uid:"), session.UID)
		fmt.Printf("          %v %v\n", color.HiBlueString("User:"), session.User)
		fmt.Printf("          %v %v\n", color.HiBlueString("Seat:"), session.Seat)
		fmt.Printf("          %v %v\n\n", color.HiBlueString("Path:"), session.Path)
	}
}

func acquireLoginUserStatus(Uid, host string, token map[string]string) {
	value, err := validator.IsInt(Uid)
	if err != nil {
		fmt.Errorf("invalid Uid: '%s'", Uid)
		return
	}

	n := login.User{
		UID: uint32(value),
	}

	var resp []byte
	resp, err = web.DispatchSocket(http.MethodGet, host, "/api/v1/system/login/getuser", token, n)
	if err != nil {
		fmt.Printf("Failed to acquire login user info: %v\n", err)
		return
	}

	u := LoginStats{}
	if err := json.Unmarshal(resp, &u); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !u.Success {
		fmt.Printf("Failed to acquire login user info: %v\n", u.Errors)
		return
	}

	fmt.Printf("          %v %v\n\n", color.HiBlueString("Path:"), u.Message)
}

func acquireLoginSessionStatus(Id, host string, token map[string]string) {
	n := login.Session{
		ID: Id,
	}

	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/system/login/getsession", token, n)
	if err != nil {
		fmt.Printf("Failed to acquire login session info: %v\n", err)
		return
	}

	s := LoginStats{}
	if err := json.Unmarshal(resp, &s); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !s.Success {
		fmt.Printf("Failed to acquire login session info: %v\n", s.Errors)
		return
	}

	fmt.Printf("          %v %v\n\n", color.HiBlueString("Path:"), s.Message)
}
