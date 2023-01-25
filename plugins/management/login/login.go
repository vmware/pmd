// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package login

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/web"
)

var loginMethod = map[string]string{
	"list-sessions":     "ListSessions",
	"list-users":        "ListUsers",
	"lock-session":      "LockSession",
	"lock-sessions":     "LockSessions",
	"terminate-session": "TerminateSession",
	"terminate-user":    "TerminateUser",
}

type Login struct {
	Path     string `json:"path"`
	Property string `json:"property"`
	Value    string `json:"value"`
}

type User struct {
	UID  uint32 `json:"UID"`
	Name string `json:"Name"`
	Path string `json:"Path"`
}

type Session struct {
	ID   string `json:"ID"`
	UID  uint32 `json:"UID"`
	User string `json:"User"`
	Seat string `json:"Seat"`
	Path string `json:"Path"`
}

func decodeSessionJSONRequest(r *http.Request) (*Session, error) {
	s := Session{}
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		return nil, err
	}

	return &s, nil
}

func decodeUserJSONRequest(r *http.Request) (*User, error) {
	u := User{}
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		return nil, err
	}

	return &u, nil
}

func AcquireUserListFromLogin(ctx context.Context, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	users, err := c.DBusAcquireUsersFromLogin(ctx)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	return web.JSONResponse(users, w)
}

func (u *User) AcquireUserFromLogin(ctx context.Context, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	users, err := c.DBusAcquireUsersFromLogin(ctx)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	user := User{}
	for _, usr := range users {
		if u.UID == usr.UID {
			user = usr
			break
		} else {
			log.Errorf("User not exist for Uid: %v", u.UID)
			return fmt.Errorf("No User '%v'", u.UID)
		}
	}

	return web.JSONResponse(user.Path, w)
}

func AcquireSessionListFromLogin(ctx context.Context, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	sessions, err := c.DBusAcquireUSessionsFromLogin(ctx)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	return web.JSONResponse(sessions, w)
}

func (s *Session) AcquireSessionFromLogin(ctx context.Context, w http.ResponseWriter) error {
	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection to the system bus: %s", err)
		return err
	}
	defer c.Close()

	session, err := c.DBusAcquireUSessionFromLogin(ctx, s.ID)
	if err != nil {
		return web.JSONResponseError(err, w)
	}

	return web.JSONResponse(session.Path, w)
}
