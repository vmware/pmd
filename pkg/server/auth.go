// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/pmd-nextgen/pkg/share"
	"github.com/pmd-nextgen/pkg/system"
	"github.com/pmd-nextgen/pkg/web"
)

func active(nbf, exp interface{}) bool {
	if unix, ok := nbf.(float64); ok {
		t := time.Unix(int64(unix), 0)
		if time.Now().Before(t) {
			return false
		}
	}
	if unix, ok := exp.(float64); ok {
		t := time.Unix(int64(unix), 0)
		if time.Now().After(t) {
			return false
		}
	}
	return true
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session-Token")
		tokenJWT, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return []byte(os.Getenv("JWT_SECRET")), nil
		})

		if err != nil {
			if ve, ok := err.(*jwt.ValidationError); ok {
				if ve.Errors&jwt.ValidationErrorMalformed != 0 {
					log.Errorf("Invalid token='%v'", tokenJWT.Raw)
					web.JSONResponseError(errors.New("invalid token"), w)
					return
				}
			}
		}

		if !tokenJWT.Valid {
			log.Errorf("Invalid token='%v'", tokenJWT.Raw)
			web.JSONResponseError(errors.New("invalid token"), w)
			return
		}

		claims, ok := tokenJWT.Claims.(jwt.MapClaims)
		if !ok {
			log.Errorf("Invalid token claims ='%v'", tokenJWT.Raw)
			web.JSONResponseError(errors.New("invalid token claims"), w)
			return
		}
		cls := map[string]interface{}{}
		for k, v := range claims {
			cls[k] = v
		}

		if !active(cls["nbf"], cls["exp"]) {
			log.Errorf("expired token", tokenJWT.Raw)
			web.JSONResponseError(errors.New("expired token"), w)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authenticateLocalUser(credentials *unix.Ucred) error {
	if credentials.Uid != 0 {
		pmUser, err := system.GetUserCredentials("pmd-nextgen")
		if err != nil {
			log.Infof("Failed to get user 'pmd-nextgen' credentials: %+v", err)
			return err
		}

		u, _ := system.GetUserCredentialsByUid(credentials.Uid)

		groups, _ := u.GroupIds()
		if !share.StringContains(groups, strconv.Itoa(int(pmUser.Gid))) {
			return errors.New("user's gid not same as pmd-nextgen's gid")
		}

		log.Debugf("Connection credentials: pid='%d', user='%s' uid='%d', gid='%d' belongs to groups='%v'", credentials.Pid, u.Username, credentials.Gid, credentials.Uid, groups)
	} else {
		log.Debugf("Connection credentials: pid='%d', user='root' uid='%d', gid='%d'", credentials.Pid, credentials.Gid, credentials.Uid)
	}

	return nil
}

func UnixDomainPeerCredential(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var credentialsContextKey = struct{}{}

		credentials := r.Context().Value(credentialsContextKey).(*unix.Ucred)

		if err := authenticateLocalUser(credentials); err != nil {
			web.JSONResponseError(err, w)
			log.Infof("Unauthorized connection. Credentials: pid='%d', uid='%d', gid='%d': %v", credentials.Pid, credentials.Gid, credentials.Uid, err)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}
