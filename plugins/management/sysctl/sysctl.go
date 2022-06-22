// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package sysctl

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	log "github.com/sirupsen/logrus"
)

const (
	sysctlDirPath = "/etc/sysctl.d"
	sysctlPath    = "/etc/sysctl.conf"
	procSysPath   = "/proc/sys"
)

// Sysctl json request
type Sysctl struct {
	Key      string   `json:"Key"`
	Value    string   `json:"Value"`
	Apply    bool     `json:"Apply"`
	Pattern  string   `json:"Pattern"`
	FileName string   `json:"FileName"`
	Files    []string `json:"Files"`
}

// Get filepath from key
func pathFromKey(key string) string {
	return path.Join(procSysPath, strings.Replace(key, ".", "/", -1))
}

// Get key from filepath
func keyFromPath(path string) string {

	subPath := strings.TrimPrefix(path, procSysPath+"/")
	return strings.Replace(subPath, "/", ".", -1)
}

// Apply sysctl configuration to system
func (s *Sysctl) apply(fileName string) error {
	stdout, err := system.ExecAndCapture("sysctl", "-p", fileName)
	if err != nil {
		log.Errorf("Failed to apply sysctl configuration file='%s' %s", fileName, stdout)
		return fmt.Errorf("Failed to apply sysctl configuration file='%s' %s", fileName, stdout)
	}

	return nil
}

// Read configuration file and prepare sysctlMap
func readSysctlConfigFromFile(path string, sysctlMap map[string]string) error {
	lines, err := system.ReadFullFile(path)
	if err != nil {
		log.Errorf("Failed to read file='%s'%v", path, err)
		return fmt.Errorf("Failed to read file='%s'%v", path, err)
	}

	for _, line := range lines {
		tokens := strings.Split(line, "=")
		if len(tokens) != 2 {
			log.Debugf("Could not parse line: '%s'", line)
			continue
		}

		k := strings.TrimSpace(tokens[0])
		v := strings.TrimSpace(tokens[1])
		sysctlMap[k] = v
	}

	return nil
}

// Write sysctlMap entry in configuration file
func writeSysctlConfigInFile(confFile string, sysctlMap map[string]string) error {
	var lines []string
	var line string

	for k, v := range sysctlMap {
		line = k + "=" + v
		lines = append(lines, line)
	}

	return system.WriteFullFile(confFile, lines)
}

// Read /etc/sysctl.conf file and prepare sysctlMap
func createSysctlMapFromConfFile(sysctlMap map[string]string) error {
	return readSysctlConfigFromFile(sysctlPath, sysctlMap)
}

// Traverse the baseDirPath and prepare sysctlMap
func createSysctlMapFromDir(baseDirPath string, sysctlMap map[string]string) error {
	err := filepath.Walk(baseDirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("Failed to access sysctl path: %v", err)
		}
		if info.IsDir() {
			return err
		}

		// Reading all files from procSysPath so need to create key and insert in map.
		if baseDirPath == procSysPath {
			key := keyFromPath(path)
			val, err := ioutil.ReadFile(path)
			if err != nil {
				log.Errorf("Failed to read file='%s': %v", path, err)
			} else {
				sysctlMap[key] = strings.TrimSpace(string(val))
			}
		} else {
			err = readSysctlConfigFromFile(path, sysctlMap)
			if err != nil {
				log.Debugf("%v", err)
			}
		}

		return nil
	})

	return err
}

// Fetch key value from proc/sys directory
func getKeyValueFromProcSys(key string, sysctlMap map[string]string) error {
	data, err := ioutil.ReadFile(pathFromKey(key))
	if err != nil {
		return err
	}

	sysctlMap[key] = strings.TrimSpace(string(data))

	return nil
}

// Get sysctl key value from any of the following
// sysctl.conf, sysctl.d or /proc/sys
func (s *Sysctl) Acquire(w http.ResponseWriter) error {
	if len(s.Key) == 0 {
		return fmt.Errorf("Failed to acquire sysctl parameter. Input key missing")
	}

	sysctlMap := make(map[string]string)

	// First try to get from sysctl.conf.
	err := createSysctlMapFromConfFile(sysctlMap)
	_, ok := sysctlMap[s.Key]
	if ok {
		return web.JSONResponse(sysctlMap[s.Key], w)
	}

	// Cant find the key from main sysctl.conf read sysctl.d dir files.
	err = createSysctlMapFromDir(sysctlDirPath, sysctlMap)
	_, ok = sysctlMap[s.Key]
	if ok {
		return web.JSONResponse(sysctlMap[s.Key], w)
	}

	// Cant find the key from sysctl.d try to get from proc/sys.
	err = getKeyValueFromProcSys(s.Key, sysctlMap)
	_, ok = sysctlMap[s.Key]
	if ok {
		return web.JSONResponse(sysctlMap[s.Key], w)
	}

	log.Debugf("Failed to determine sysctl key[%s] value from all configs: %v", s.Key, err)

	return err
}

// GetPatern will return all the entry with matching pattern
// If pattern is empty it should return all values
func (s *Sysctl) GetPattern(w http.ResponseWriter) error {
	if validator.IsEmpty(s.Pattern) {
		log.Infof("Input pattern is empty return all system configuration")
	}

	re, err := regexp.CompilePOSIX(s.Pattern)
	if err != nil {
		return fmt.Errorf("Failed to acquire sysctl parameter, Invalid pattern='%s': %v", s.Pattern, err)
	}

	sysctlMap := make(map[string]string)
	if err := createSysctlMapFromConfFile(sysctlMap); err != nil {
		log.Debugf("Failed to read configuration from '%s': %v", sysctlPath, err)
	}

	if err := createSysctlMapFromDir(sysctlDirPath, sysctlMap); err != nil {
		log.Debugf("Failed to read configuration from '%s': %v", sysctlDirPath, err)
	}

	if err := createSysctlMapFromDir(procSysPath, sysctlMap); err != nil {
		log.Errorf("Failed to read configuration from '%s': %v", procSysPath, err)
		return err
	}

	result := make(map[string]string)
	for k, v := range sysctlMap {
		if !re.MatchString(k) {
			continue
		}
		result[k] = v
	}
	return web.JSONResponse(result, w)
}

// Update sysctl configuration file and apply
// Action can be SET, UPDATE or DELETE
func (s *Sysctl) Update(w http.ResponseWriter) error {
	if validator.IsEmpty(s.FileName) {
		s.FileName = sysctlPath
	} else {
		s.FileName = filepath.Join(sysctlDirPath, s.FileName)
	}

	if validator.IsEmpty(s.Key) {
		log.Errorf("input Key is missing in json data")
		return fmt.Errorf("input Key is missing in json data")
	}

	if validator.IsEmpty(s.Value) {
		log.Errorf("input Value is missing in json data")
		return fmt.Errorf("input Value is missing in json data")
	}

	sysctlMap := make(map[string]string)
	if err := readSysctlConfigFromFile(s.FileName, sysctlMap); err != nil {
		log.Errorf("%v", err)
		return fmt.Errorf("%v", err)
	}

	if s.Value == "Delete" {
		_, ok := sysctlMap[s.Key]
		if !ok {
			log.Errorf("Failed to remove sysctl parameter '%s'. Key not found", s.Key)
			return fmt.Errorf("Failed to remove sysctl parameter '%s'. Key not found", s.Key)
		}
		delete(sysctlMap, s.Key)
	} else {
		sysctlMap[s.Key] = s.Value
	}

	// Update config file and apply.
	if err := writeSysctlConfigInFile(s.FileName, sysctlMap); err != nil {
		log.Errorf("Failed to update file='%s': %v", s.FileName, err)
		return fmt.Errorf("Failed to update file='%s': %v", s.FileName, err)
	}
	if s.Apply {
		if err := s.apply(s.FileName); err != nil {
			return err
		}
	}

	return web.JSONResponse("Configuration updated", w)
}

// Load all the configuration files and apply
func (s *Sysctl) Load(w http.ResponseWriter) error {
	if validator.IsArrayEmpty(s.Files) {
		s.Files = []string{sysctlPath}
	}

	sysctlMap := make(map[string]string)
	for _, f := range s.Files {
		if f != sysctlPath {
			f = filepath.Join(sysctlDirPath, f)
		}

		if err := readSysctlConfigFromFile(f, sysctlMap); err != nil {
			log.Errorf("Failed to load sysctl configuration from file='%s': %v", f, err)
			return fmt.Errorf("%v", err)
		}
	}

	if err := writeSysctlConfigInFile(sysctlPath, sysctlMap); err != nil {
		return err
	}
	if s.Apply {
		if err := s.apply(sysctlPath); err != nil {
			return err
		}
	}

	return web.JSONResponse("Configuration loaded", w)
}
