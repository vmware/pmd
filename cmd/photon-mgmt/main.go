// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"

	"github.com/vmware/pmd/pkg/conf"
	"github.com/vmware/pmd/pkg/server"
	"github.com/vmware/pmd/pkg/system"
)

func main() {
	c, err := conf.Parse()
	if err != nil {
		log.Errorf("Failed to parse conf file %s: %s", conf.ConfFile, err)
	}

	log.Infof("photon-mgmtd: v%s (built %s)", conf.Version, runtime.Version())

	cred, err := system.GetUserCredentials("")
	if err != nil {
		log.Warningf("Failed to get current user credentials: %+v", err)
		os.Exit(1)
	} else {
		if cred.Uid == 0 {
			u, err := system.GetUserCredentials("photon-mgmt")
			if err != nil {
				log.Errorf("Failed to get user 'photon-mgmt' credentials: %+v", err)
				os.Exit(1)
			} else {
				if err := system.CreateStateDirs("/run/photon-mgmt", int(u.Uid), int(u.Gid)); err != nil {
					log.Errorf("Failed to create runtime dir '/run/photon-mgmt': %+v", err)
					os.Exit(1)
				}

				if err := system.EnableKeepCapability(); err != nil {
					log.Warningf("Failed to enable keep capabilities: %+v", err)
				}

				if err := system.SwitchUser(u); err != nil {
					log.Warningf("Failed to switch user: %+v", err)
				}

				if err := system.DisableKeepCapability(); err != nil {
					log.Warningf("Failed to disable keep capabilities: %+v", err)
				}

				err := system.ApplyCapability(u)
				if err != nil {
					log.Warningf("Failed to apply capabilities: +%v", err)
				}
			}
		}
	}

	if err := server.Run(c); err != nil {
		log.Fatalf("Failed to start photon-mgmtd: %v", err)
		os.Exit(1)
	}
}
