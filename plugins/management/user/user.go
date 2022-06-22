// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package user

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/pmd-nextgen/pkg/system"
	"github.com/pmd-nextgen/pkg/web"
)

const (
	userFile     = "/run/photon-mgmt/users"
	userInfoPath = "/etc/passwd"
)

type User struct {
	Uid           string   `json:"Uid"`
	Gid           string   `json:"Gid"`
	Groups        []string `json:"Groups"`
	Comment       string   `json:"Comment"`
	HomeDirectory string   `json:"HomeDir"`
	Shell         string   `json:"Shell"`
	Name          string   `json:"Name"`
	Password      string   `json:"Password"`
}

// Read /etc/passwd file and prepare userInfoList.
func readAndCreateUserInfoList() ([]User, error) {
	var userInfoList []User
	lines, err := system.ReadFullFile(userInfoPath)
	if err != nil {
		return userInfoList, fmt.Errorf("Failed to %v", err)
	}

	for _, line := range lines {
		userInfo := strings.FieldsFunc(line, func(delim rune) bool {
			return delim == ':'
		})

		if len(userInfo) > 0 {
			usr, err := user.Lookup(userInfo[0])
			if err != nil {
				log.Debug("Failed to find user='%s': %v", userInfo[0], err)
				continue
			}

			u := User{
				Name:          usr.Username,
				Uid:           usr.Uid,
				Gid:           usr.Gid,
				Comment:       usr.Name,
				HomeDirectory: usr.HomeDir,
			}

			userInfoList = append(userInfoList, u)
		}
	}

	return userInfoList, err
}

func (u *User) update() error {
	if u.HomeDirectory == "" {
		u.HomeDirectory = path.Join("/home", u.Name)
	}
	if u.Shell == "" {
		path, err := exec.LookPath("bash")
		if err != nil {
			return err
		}

		u.Shell = path
	}

	// pw_name:pw_passwd:pw_uid:pw_gid:pw_gecos:pw_dir:pw_shell
	line := u.Name + ":" + u.Password + ":" + u.Uid + ":" + u.Gid + ":" + u.Comment + ":" + u.HomeDirectory + ":" + u.Shell
	if err := system.WriteOneLineFile(userFile, line); err != nil {
		return err
	}
	defer os.Remove(userFile)

	if s, err := system.ExecAndCapture("newusers", userFile); err != nil {
		log.Errorf("Failed to add user '%s': %s (%v)", u.Name, s, err)
		return fmt.Errorf("%s (%v)", s, err)
	}

	return nil
}

func (u *User) Add(w http.ResponseWriter) error {
	var c *syscall.Credential
	var err error

	if c, err = system.GetUserCredentials(u.Name); err != nil {
		_, ok := err.(user.UnknownUserError)
		if !ok {
			return err
		}
	}
	if c != nil {
		return fmt.Errorf("user='%s', gid='%d' already exists", u.Name, c.Gid)
	}

	if u.Uid != "" {
		id, err := user.LookupId(u.Uid)
		if err != nil {
			_, ok := err.(user.UnknownUserError)
			if !ok {
				return err
			}
		}
		if id != nil {
			return fmt.Errorf("user='%s', gid='%s' already exists", u.Name, id.Uid)
		}
	}

	if err := u.update(); err != nil {
		return err
	}

	return web.JSONResponse("user added", w)
}

func (u *User) Remove(w http.ResponseWriter) error {
	if _, err := system.GetUserCredentials(u.Name); err != nil {
		return err
	}

	if s, err := system.ExecAndCapture("userdel", u.Name); err != nil {
		log.Errorf("Failed to delete user '%s': %s (%v)", u.Name, s)
		return fmt.Errorf("%s (%v)", s, err)
	}

	return web.JSONResponse("user removed", w)
}

func (u *User) Modify(w http.ResponseWriter) error {
	if _, err := system.GetUserCredentials(u.Name); err != nil {
		return err
	}

	if err := u.update(); err != nil {
		return err
	}

	return web.JSONResponse("user modified", w)
}

func (u *User) View(w http.ResponseWriter) error {
	userInfoList, err := readAndCreateUserInfoList()
	if err != nil {
		log.Errorf("Failed to get user info from '%s' : (%v)", userInfoPath, err)
		return fmt.Errorf("(%v)", err)
	}

	return web.JSONResponse(userInfoList, w)
}
