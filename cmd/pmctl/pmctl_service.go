// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/fatih/color"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/systemd"
)

type UnitStatus struct {
	Success bool               `json:"success"`
	Message systemd.UnitStatus `json:"message"`
	Errors  string             `json:"errors"`
}

func executeSystemdUnitCommand(command string, unit string, host string, token map[string]string) {
	c := systemd.UnitAction{
		Action: command,
		Unit:   unit,
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/service/systemd", token, c)
	if err != nil {
		fmt.Printf("Failed to execute systemd command: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to execute systemd command: %v\n", m.Errors)
	}
}

func acquireSystemdUnitStatus(unit string, host string, token map[string]string) {
	resp, err := web.DispatchSocket(http.MethodGet, host, "/api/v1/service/systemd/"+unit+"/status", token, nil)
	if err != nil {
		fmt.Printf("Failed to fetch unit status: %v\n", err)
		return
	}

	u := UnitStatus{}
	if err := json.Unmarshal(resp, &u); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if u.Success {
		fmt.Printf("                   %v %+v \n", color.HiBlueString("Name:"), u.Message.Name)
		fmt.Printf("            %v %+v \n", color.HiBlueString("Description:"), u.Message.Description)
		fmt.Printf("               %v %+v \n", color.HiBlueString("Main Pid:"), u.Message.MainPid)
		fmt.Printf("             %v %+v \n", color.HiBlueString("Load State:"), u.Message.LoadState)
		fmt.Printf("           %v %+v \n", color.HiBlueString("Active State:"), u.Message.ActiveState)
		fmt.Printf("              %v %+v \n", color.HiBlueString("Sub State:"), u.Message.SubState)
		fmt.Printf("        %v %+v \n", color.HiBlueString("Unit File State:"), u.Message.UnitFileState)

		if u.Message.StateChangeTimestamp > 0 {
			t := time.Unix(int64(u.Message.StateChangeTimestamp), 0)
			fmt.Printf(" %v %+v \n", color.HiBlueString("State Change TimeStamp:"), t.Format(time.UnixDate))
		} else {
			fmt.Printf(" %v %+v \n", color.HiBlueString("State Change TimeStamp:"), 0)
		}

		if u.Message.ActiveEnterTimestamp > 0 {
			t := time.Unix(int64(u.Message.ActiveEnterTimestamp), 0)
			fmt.Printf(" %v %+v \n", color.HiBlueString("Active Enter Timestamp:"), t.Format(time.UnixDate))
		} else {
			fmt.Printf(" %v %+v \n", color.HiBlueString("Active Enter Timestamp:"), 0)
		}

		if u.Message.ActiveEnterTimestamp > 0 {
			t := time.Unix(int64(u.Message.InactiveExitTimestamp), 0)
			fmt.Printf("%v %+v \n", color.HiBlueString("Inactive Exit Timestamp:"), t.Format(time.UnixDate))
		} else {
			fmt.Printf("%v %+v \n", color.HiBlueString("Inactive Exit Timestamp:"), 0)
		}

		if u.Message.ActiveExitTimestamp > 0 {
			t := time.Unix(int64(u.Message.ActiveExitTimestamp), 0)
			fmt.Printf("  %v %+v \n", color.HiBlueString("Active Exit Timestamp:"), t.Format(time.UnixDate))
		} else {
			fmt.Printf("  %v %+v \n", color.HiBlueString("Active Exit Timestamp:"), 0)
		}

		if u.Message.InactiveExitTimestamp > 0 {
			t := time.Unix(int64(u.Message.InactiveExitTimestamp), 0)
			fmt.Printf("%v %+v \n", color.HiBlueString("Inactive Exit Timestamp:"), t.Format(time.UnixDate))
		} else {
			fmt.Printf("%v %+v \n", color.HiBlueString("Inactive Exit Timestamp:"), 0)
		}

		switch u.Message.ActiveState {
		case "active", "reloading":
			if u.Message.ActiveEnterTimestamp > 0 {
				t := time.Unix(int64(u.Message.ActiveEnterTimestamp), 0)
				fmt.Printf("                 %v %s (%s) since %v\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState, t.Format(time.UnixDate))
			} else {
				fmt.Printf("                 %v %s (%s)\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState)
			}
		case "inactive", "failed":
			if u.Message.ActiveExitTimestamp != 0 {
				t := time.Unix(int64(u.Message.InactiveExitTimestamp), 0)
				fmt.Printf("                 %v %s (%s) since %v\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState, t.Format(time.UnixDate))
			} else {
				fmt.Printf("                 %v %s (%s)\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState)
			}
		case "activating":
			var t time.Time

			if u.Message.ActiveExitTimestamp > 0 || u.Message.ActiveEnterTimestamp > 0 {
				if u.Message.ActiveExitTimestamp > 0 {
					t = time.Unix(int64(u.Message.ActiveEnterTimestamp), 0)
				} else if u.Message.ActiveEnterTimestamp > 0 {
					t = time.Unix(int64(u.Message.ActiveEnterTimestamp), 0)
				}

				fmt.Printf("                %v %s (%s) %v\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState, t.Format(time.UnixDate))
			} else {
				fmt.Printf("                %v %s (%s)\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState)
			}
		default:
			t := time.Unix(int64(u.Message.ActiveExitTimestamp), 0)
			fmt.Printf("                %v %s (%s) ago %v\n", color.HiBlueString("Active:"), u.Message.ActiveState, u.Message.SubState, t.Format(time.UnixDate))
		}
	} else {
		fmt.Println(u.Errors)
	}
}
