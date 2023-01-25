// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package group

import (
	"fmt"
	"net/http"
	"os/user"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/web"
)

const (
	groupInfoPath = "/etc/group"
)

type Group struct {
	Gid     string `json:"Gid"`
	Name    string `json:"Name"`
	NewName string `json:"NewName"`
}

// Read /etc/group file and prepare groupInfoList.
func readAndCreateGroupInfoList() ([]Group, error) {
	var groupInfoList []Group
	lines, err := system.ReadFullFile(groupInfoPath)
	if err != nil {
		return groupInfoList, fmt.Errorf("Failed to %v", err)
	}

	for _, line := range lines {
		groupInfo := strings.FieldsFunc(line, func(delim rune) bool {
			return delim == ':'
		})

		if len(groupInfo) > 0 {
			g := Group{
				Name: groupInfo[0],
				Gid:  groupInfo[2],
			}

			groupInfoList = append(groupInfoList, g)
		}
	}

	return groupInfoList, err
}

func (g *Group) GroupAdd(w http.ResponseWriter) error {
	var grp *user.Group
	var err error

	if grp, err = user.LookupGroup(g.Name); err != nil {
		_, ok := err.(user.UnknownGroupError)
		if !ok {
			return err
		}
	}
	if grp != nil {
		return fmt.Errorf("group %s already exists", grp.Name)
	}

	if g.Gid != "" {
		id, err := user.LookupGroupId(g.Gid)
		if err != nil {
			_, ok := err.(user.UnknownGroupIdError)
			if !ok {
				return err
			}
		}
		if id != nil {
			return fmt.Errorf(" gid '%v' already exists", id.Gid)
		}
	}

	if g.Gid != "" {
		if s, err := system.ExecAndCapture("groupadd", g.Name, "-g", g.Gid); err != nil {
			return fmt.Errorf("%s (%v)", s, err)
		}
	} else {
		if s, err := system.ExecAndCapture("groupadd", g.Name); err != nil {
			return fmt.Errorf("%s (%v)", s, err)
		}
	}
	return web.JSONResponse("group added", w)
}

func (g *Group) GroupRemove(w http.ResponseWriter) error {
	if _, err := system.GetGroupCredentials(g.Name); err != nil {
		return err
	}

	if s, err := system.ExecAndCapture("groupdel", g.Name); err != nil {
		log.Errorf("Failed to remove group '%s': %s (%v)", g.Name, s, err)
		return fmt.Errorf("%s (%v)", s, err)
	}

	return web.JSONResponse("group removed", w)
}

func (g *Group) GroupModify(w http.ResponseWriter) error {
	if _, err := system.GetGroupCredentials(g.Name); err != nil {
		return err
	}

	if s, err := system.ExecAndCapture("groupmod", "-n", g.NewName, g.Name); err != nil {
		log.Errorf("Failed to modify group '%s': %s (%v)", g.Name, s, err)
		return fmt.Errorf("%s (%v)", s, err)
	}

	return web.JSONResponse("group modified", w)
}

func (g *Group) GroupView(w http.ResponseWriter) error {
	groupInfoList, err := readAndCreateGroupInfoList()
	if err != nil {
		log.Errorf("Failed to get group info from '%s' : (%v)", groupInfoPath, err)
		return fmt.Errorf("(%v)", err)
	}

	if g.Name != "" {
		found := false
		for _, grp := range groupInfoList {
			if grp.Name == g.Name {
				groupInfoList = nil
				groupInfoList = append(groupInfoList, grp)
				found = true
				break
			}
		}
		if !found {
			log.Errorf("Group does not exist on system '%s'", g.Name)
			return fmt.Errorf("Unknown group '%s'", g.Name)
		}
	}

	return web.JSONResponse(groupInfoList, w)
}
