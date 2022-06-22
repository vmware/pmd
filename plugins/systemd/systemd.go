// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package systemd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"

	sd "github.com/coreos/go-systemd/v22/dbus"
	log "github.com/sirupsen/logrus"

	"github.com/pmd-nextgen/pkg/system"
	"github.com/pmd-nextgen/pkg/web"
)

type UnitAction struct {
	Action   string `json:"Action"`
	Unit     string `json:"Unit"`
	UnitType string `json:"UnitType"`
	Property string `json:"Property"`
	Value    string `json:"Value"`
}

type Property struct {
	Property string `json:"property"`
	Value    string `json:"value"`
}

type UnitStatus struct {
	Status                 string `json:"Property"`
	Unit                   string `json:"Unit"`
	Name                   string `json:"Name"`
	Description            string `json:"Description"`
	MainPid                uint32 `json:"MainPid"`
	LoadState              string `json:"LoadState"`
	ActiveState            string `json:"ActiveState"`
	SubState               string `json:"SubState"`
	Followed               string `json:"Followed"`
	Path                   string `json:"Path"`
	JobId                  uint32 `json:"JobId"`
	JobType                string `json:"JobType"`
	JobPath                string `json:"JobPath"`
	UnitFileState          string `json:"UnitFileState"`
	StateChangeTimestamp   int64  `json:"StateChangeTimestamp"`
	InactiveExitTimestamp  int64  `json:"InactiveExitTimestamp"`
	ActiveEnterTimestamp   int64  `json:"ActiveEnterTimestamp"`
	ActiveExitTimestamp    int64  `json:"ActiveExitTimestamp"`
	InactiveEnterTimestamp int64  `json:"InactiveEnterTimestamp"`
}

type Describe struct {
	Version        string `json:"Version"`
	Features       string `json:"Features"`
	Virtualization string `json:"Virtualization"`
	Architecture   string `json:"Architecture"`
	Tainted        string `json:"Tainted"`
	NNames         string `json:"NNames"`
	ControlGroup   string `json:"ControlGroup"`
	SystemState    string `json:"SystemState"`
}

func ManagerDescribe(ctx context.Context) (*Describe, error) {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus: %s", err)
		return nil, err
	}
	defer conn.Close()

	d := Describe{}

	var wg sync.WaitGroup
	wg.Add(8)

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("Version")
		if err == nil {
			json.Unmarshal([]byte(v), &d.Version)
		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("Features")
		if err == nil {
			json.Unmarshal([]byte(v), &d.Features)
		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("Virtualization")
		if err == nil {
			json.Unmarshal([]byte(v), &d.Virtualization)

		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("Architecture")
		if err == nil {
			json.Unmarshal([]byte(v), &d.Architecture)
		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("Tainted")
		if err == nil {
			json.Unmarshal([]byte(v), &d.Tainted)
		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("NNames")
		if err == nil {
			json.Unmarshal([]byte(v), &d.NNames)
		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("ControlGroup")
		if err == nil {
			json.Unmarshal([]byte(v), &d.ControlGroup)
		}
	}()

	go func() {
		defer wg.Done()

		v, err := conn.GetManagerProperty("SystemState")
		if err == nil {
			json.Unmarshal([]byte(v), &d.SystemState)
		}
	}()

	wg.Wait()

	return &d, nil
}

func ManagerAcquireSystemProperty(ctx context.Context, w http.ResponseWriter, property string) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus: %s", err)
		return err
	}
	defer conn.Close()

	v, err := conn.GetManagerProperty(property)
	if err != nil {
		log.Errorf("Failed fetch systemd manager property='%s': %v", property, err)
		return err
	}

	s, err := strconv.Unquote(string(v))
	if err != nil {
		log.Errorf("Failed to unquote systemd manager property='%s`: %v", property, err)
		return err
	}

	p := Property{
		Property: property,
		Value:    s,
	}
	return web.JSONResponse(p, w)
}

func ListUnits(ctx context.Context, w http.ResponseWriter) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus: %s", err)
		return err
	}
	defer conn.Close()

	units, err := conn.ListUnitsContext(ctx)
	if err != nil {
		log.Errorf("Failed list systemd units: %v", err)
		return err
	}

	return web.JSONResponse(units, w)
}

func (u *UnitAction) UnitCommands(ctx context.Context) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus: %v", err)
		return err
	}
	defer conn.Close()

	c := make(chan string)
	switch u.Action {
	case "start":
		jid, err := conn.StartUnitContext(ctx, u.Unit, "replace", c)
		if err != nil {
			log.Errorf("Failed to start systemd unit='%s': %v", u.Unit, err)
			return err
		}

		log.Debugf("Successfully executed 'start' on systemd unit='%s' job_id='%d'", u.Unit, jid)

	case "stop":
		jid, err := conn.StopUnitContext(ctx, u.Unit, "fail", c)
		if err != nil {
			log.Errorf("Failed to stop systemd unit='%s': %v", u.Unit, err)
			return err
		}

		log.Debugf("Successfully executed 'stop' on systemd unit='%s' job_id='%d'", u.Unit, jid)

	case "restart":
		jid, err := conn.RestartUnitContext(ctx, u.Unit, "replace", c)
		if err != nil {
			log.Errorf("Failed to restart systemd unit='%s': %v", u.Unit, err)
			return err
		}

		log.Debugf("Successfully executed 'restart' on systemd unit='%s' job_id='%d'", u.Unit, jid)

	case "try-restart":
		jid, err := conn.TryRestartUnitContext(ctx, u.Unit, "replace", c)
		if err != nil {
			log.Errorf("Failed to try restart systemd unit='%s': %v", u.Unit, err)
			return err
		}

		log.Debugf("Successfully executed 'try-restart' on systemd unit='%s' job_id='%d'", u.Unit, jid)

	case "reload-or-restart":
		jid, err := conn.ReloadOrRestartUnitContext(ctx, u.Unit, "replace", c)
		if err != nil {
			log.Errorf("Failed to reload or restart systemd unit='%s': %v", u.Unit, err)
			return err
		}

		log.Debugf("Successfully executed 'reload-or-restart' on systemd unit='%s' job_id='%d'", u.Unit, jid)

	case "reload":
		jid, err := conn.ReloadUnitContext(ctx, u.Unit, "replace", c)
		if err != nil {
			log.Errorf("Failed to reload systemd unit='%s': %v", u.Unit, err)
			return err
		}

		log.Debugf("Successfully executed 'reload' on systemd unit='%s' job_id='%d'", u.Unit, jid)

	case "enable":
		install, changes, err := conn.EnableUnitFilesContext(ctx, []string{u.Unit}, false, true)
		if err != nil {
			log.Errorf("Failed to enable systemd unit='%s': %v", u.Value, err)
			return err
		}

		log.Debugf("Successfully executed 'enable' on systemd unit='%s' install='%t' changes='%s'", u.Unit, install, changes)

	case "disable":
		changes, err := conn.DisableUnitFilesContext(ctx, []string{u.Unit}, false)
		if err != nil {
			log.Errorf("Failed to disable systemd unit='%s': %v", u.Value, err)
			return err
		}

		log.Debugf("Successfully executed 'disable' on systemd unit='%s' changes='%s'", u.Unit, changes)

	case "mask":
		changes, err := conn.MaskUnitFilesContext(ctx, []string{u.Unit}, false, true)
		if err != nil {
			log.Errorf("Failed to mask systemd unit='%s': %v", u.Value, err)
			return err
		}

		log.Debugf("Successfully executed 'mask' on systemd unit='%s' changes='%s'", u.Unit, changes)

	case "unmask":
		changes, err := conn.UnmaskUnitFilesContext(ctx, []string{u.Unit}, false)
		if err != nil {
			log.Errorf("Failed to unmask systemd unit='%s': %v", u.Value, err)
			return err
		}

		log.Debugf("Successfully executed 'unmask' on systemd unit='%s' changes='%s'", u.Unit, changes)

	case "kill":
		signal, err := strconv.ParseInt(u.Value, 10, 64)
		if err != nil {
			log.Errorf("Failed to parse signal number='%s': %s", u.Value, err)
			return err
		}

		conn.KillUnitContext(ctx, u.Unit, int32(signal))

	default:
		log.Errorf("Unknown unit command='%s' for systemd unit='%s'", u.Action, u.Unit)
		return errors.New("unknown unit command")
	}

	return nil
}

func (u *UnitAction) AcquireUnitStatus(ctx context.Context, w http.ResponseWriter) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus:: %v", err)
		return err
	}
	defer conn.Close()

	units, err := conn.ListUnitsByNamesContext(ctx, []string{u.Unit})
	if err != nil {
		log.Errorf("Failed fetch systemd unit='%s' status: %v", u.Unit, err)
		return err
	}

	unit := UnitStatus{
		Unit:        u.Unit,
		Name:        units[0].Name,
		Status:      units[0].ActiveState,
		LoadState:   units[0].LoadState,
		Description: units[0].Description,
		ActiveState: units[0].ActiveState,
		SubState:    units[0].SubState,
		Followed:    units[0].Followed,
		Path:        string(units[0].Path),
		JobType:     units[0].JobType,
		JobPath:     string(units[0].JobPath),
	}

	var wg sync.WaitGroup
	wg.Add(len(units) * 7)

	go func() {
		defer wg.Done()
		if pid, err := conn.GetServicePropertyContext(ctx, u.Unit, "MainPID"); err == nil {
			if n, ok := pid.Value.Value().(uint32); ok {
				unit.MainPid = n
			}
		}
	}()

	go func() {
		defer wg.Done()
		if st, err := conn.GetUnitPropertyContext(ctx, u.Unit, "UnitFileState"); err == nil {
			s, _ := strconv.Unquote(st.Value.String())
			unit.UnitFileState = s
		}
		defer wg.Done()
		if ts, err := conn.GetUnitPropertyContext(ctx, u.Unit, "StateChangeTimestamp"); err == nil {
			if t, err := system.DBusTimeToUsec(ts); err != nil {
				unit.StateChangeTimestamp = 0
			} else {
				unit.StateChangeTimestamp = t.Unix()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if ts, err := conn.GetUnitPropertyContext(ctx, u.Unit, "InactiveExitTimestamp"); err == nil {
			if t, err := system.DBusTimeToUsec(ts); err != nil {
				unit.InactiveExitTimestamp = 0
			} else {
				unit.InactiveExitTimestamp = t.Unix()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if ts, err := conn.GetUnitPropertyContext(ctx, u.Unit, "ActiveEnterTimestamp"); err == nil {
			if t, err := system.DBusTimeToUsec(ts); err != nil {
				unit.ActiveEnterTimestamp = 0
			} else {
				unit.ActiveEnterTimestamp = t.Unix()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if ts, err := conn.GetUnitPropertyContext(ctx, u.Unit, "ActiveExitTimestamp"); err == nil {
			if t, err := system.DBusTimeToUsec(ts); err != nil {
				unit.ActiveExitTimestamp = 0
			} else {
				unit.ActiveExitTimestamp = t.Unix()
			}
		}
	}()

	go func() {
		defer wg.Done()
		if ts, err := conn.GetUnitPropertyContext(ctx, u.Unit, "InactiveEnterTimestamp"); err == nil {
			if t, err := system.DBusTimeToUsec(ts); err != nil {
				unit.InactiveEnterTimestamp = 0
			} else {
				unit.InactiveEnterTimestamp = t.Unix()
			}
		}
	}()

	wg.Wait()

	if ctx.Err() != nil {
		log.Errorf("Failed fetch systemd unit='%s' status: %v", u.Unit, err)
		return err
	}

	return web.JSONResponse(unit, w)
}

func (u *UnitAction) AcquireUnitProperty(ctx context.Context, w http.ResponseWriter) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus: %v", err)
		return err
	}
	defer conn.Close()

	p, err := conn.GetUnitPropertiesContext(ctx, u.Unit)
	if err != nil {
		log.Errorf("Failed to fetch systemd unit='%s' properties: %v", u.Unit, err)
		return err
	}

	return web.JSONResponse(p, w)
}

func (u *UnitAction) AcquireAllUnitProperty(ctx context.Context, w http.ResponseWriter) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus: %v", err)
		return err
	}
	defer conn.Close()

	p, err := conn.GetAllPropertiesContext(ctx, u.Unit)
	if err != nil {
		log.Errorf("Failed to fetch systemd unit='%s' properties: %v", u.Unit, err)
		return err
	}

	return web.JSONResponse(p, w)
}

func (u *UnitAction) AcquireUnitTypeProperty(ctx context.Context, w http.ResponseWriter) error {
	conn, err := sd.NewSystemdConnectionContext(ctx)
	if err != nil {
		log.Errorf("Failed to establish connection with system bus:: %v", err)
		return err
	}
	defer conn.Close()

	p, err := conn.GetUnitTypePropertiesContext(ctx, u.Unit, u.UnitType)
	if err != nil {
		log.Errorf("Failed to fetch unit type properties unit='%s': %v", u.Unit, err)
		return err
	}

	return web.JSONResponse(p, w)
}
