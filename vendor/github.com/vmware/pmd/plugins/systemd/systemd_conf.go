// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package systemd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/go-ini/ini"
	"github.com/vmware/pmd/pkg/web"
	log "github.com/sirupsen/logrus"
)

const (
	systemConfPath = "/etc/systemd/system.conf"
)

var systemConfig = map[string]string{}

func writeSystemConfig() error {
	f, err := os.OpenFile(systemConfPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)

	conf := "[Manager]\n"
	for k, v := range systemConfig {
		if v != "" {
			conf += k + "=" + v
		} else {
			conf += "#" + k + "="
		}
		conf += "\n"
	}

	fmt.Fprintln(w, conf)
	w.Flush()

	return nil
}

func readSystemConf() error {
	cfg, err := ini.Load(systemConfPath)
	if err != nil {
		return err
	}

	for k := range systemConfig {
		systemConfig[k] = cfg.Section("Manager").Key(k).String()
	}

	return nil
}

func GetSystemConf(rw http.ResponseWriter) error {
	if err := readSystemConf(); err != nil {
		return err
	}

	return web.JSONResponse(systemConfig, rw)
}

func UpdateSystemConf(rw http.ResponseWriter, r *http.Request) error {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Errorf("Failed to parse HTTP request: %v", err)
		return err
	}

	conf := make(map[string]string)
	if err = json.Unmarshal([]byte(body), &conf); err != nil {
		log.Errorf("Failed to Decode HTTP request to json: %v", err)
		return err
	}

	if err := readSystemConf(); err != nil {
		return err
	}

	for k, v := range conf {
		_, ok := systemConfig[k]
		if ok {
			systemConfig[k] = v
		}
	}

	if err = writeSystemConfig(); err != nil {
		log.Errorf("Failed Write to system conf: %v", err)
		return err
	}

	return web.JSONResponse(systemConfig, rw)
}

func InitSystemd() {
	systemConfig["LogLevel"] = ""
	systemConfig["LogTarget"] = ""
	systemConfig["LogColor"] = ""
	systemConfig["LogLocation"] = ""
	systemConfig["DumpCore"] = ""
	systemConfig["ShowStatus"] = ""
	systemConfig["CrashChangeVT"] = ""
	systemConfig["CrashShell"] = ""
	systemConfig["CrashReboot"] = ""
	systemConfig["CtrlAltDelBurstAction"] = ""
	systemConfig["CPUAffinity"] = ""
	systemConfig["JoinControllers"] = ""
	systemConfig["RuntimeWatchdogSec"] = ""
	systemConfig["ShutdownWatchdogSec"] = ""
	systemConfig["CapabilityBoundingSe"] = ""
	systemConfig["SystemCallArchitectures"] = ""
	systemConfig["TimerSlackNSec"] = ""
	systemConfig["DefaultTimerAccuracySec"] = ""
	systemConfig["DefaultStandardOutput"] = ""
	systemConfig["DefaultStandardError"] = ""
	systemConfig["DefaultTimeoutStartSec"] = ""
	systemConfig["DefaultTimeoutStopSec"] = ""
	systemConfig["DefaultRestartSec"] = ""
	systemConfig["DefaultStartLimitIntervalSec"] = ""
	systemConfig["DefaultStartLimitBurst"] = ""
	systemConfig["DefaultEnvironment"] = ""
	systemConfig["DefaultCPUAccounting"] = ""
	systemConfig["DefaultIOAccounting"] = ""
	systemConfig["DefaultIPAccounting"] = ""
	systemConfig["DefaultBlockIOAccounting"] = ""
	systemConfig["DefaultMemoryAccounting"] = ""
	systemConfig["DefaultTasksAccounting"] = ""
	systemConfig["DefaultTasksMax"] = ""
	systemConfig["DefaultLimitCPU"] = ""
	systemConfig["DefaultLimitFSIZE"] = ""
	systemConfig["DefaultLimitDATA"] = ""
	systemConfig["DefaultLimitSTACK"] = ""
	systemConfig["DefaultLimitCORE"] = ""
	systemConfig["DefaultLimitRSS"] = ""
	systemConfig["DefaultLimitNOFILE"] = ""
	systemConfig["DefaultLimitAS"] = ""
	systemConfig["DefaultLimitNPROC"] = ""
	systemConfig["DefaultLimitMEMLOCK"] = ""
	systemConfig["DefaultLimitLOCKS"] = ""
	systemConfig["DefaultLimitSIGPENDING"] = ""
	systemConfig["DefaultLimitMSGQUEUE"] = ""
	systemConfig["DefaultLimitNICE"] = ""
	systemConfig["DefaultLimitRTPRIO"] = ""
	systemConfig["DefaultLimitRTTIME"] = ""
	systemConfig["IPAddressAllow"] = ""
	systemConfig["IPAddressDeny"] = ""
}
