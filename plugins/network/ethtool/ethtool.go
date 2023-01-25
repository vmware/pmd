// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package ethtool

import (
	"encoding/json"
	"net/http"

	"github.com/vmware/pmd/pkg/parser"
	"github.com/vmware/pmd/pkg/web"
	"github.com/safchain/ethtool"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Ethtool struct {
	Action   string `json:"action"`
	Link     string `json:"link"`
	Property string `json:"property"`
	Value    string `json:"value"`
}

func (r *Ethtool) AcquireEthTool(w http.ResponseWriter) error {
	_, err := netlink.LinkByName(r.Link)
	if err != nil {
		log.Errorf("Failed to find link='%s': %v", r.Link, err)
		return err
	}

	e, err := ethtool.NewEthtool()
	if err != nil {
		log.Errorf("Failed to init ethtool for link='%s': %v", r.Link, err)
		return err
	}
	defer e.Close()

	outputSlice := []interface{}{}
	stats, err := e.Stats(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool statitics for link='%s': %v", r.Link, err)
	} else {
		outputSlice = append(outputSlice, stats)
	}

	features, err := e.Features(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool features for link='%s': %v", r.Link, err)
	} else {
		outputSlice = append(outputSlice, features)
	}

	bus, err := e.BusInfo(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool bus for link='%s': %v", r.Link, err)
	} else {
		b := struct {
			Bus string
		}{
			bus,
		}

		outputSlice = append(outputSlice, b)
	}

	driver, err := e.DriverName(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool driver name for link='%s': %v", r.Link, err)
	} else {
		d := struct {
			Driver string
		}{
			driver,
		}

		outputSlice = append(outputSlice, d)
	}

	d, err := e.DriverInfo(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool driver name for link='%s': %v", r.Link, err)
	} else {
		outputSlice = append(outputSlice, d)
	}

	permaddr, err := e.PermAddr(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool Perm Addr for link='%s': %v", r.Link, err)
	} else {
		p := struct {
			PermAddr string
		}{
			permaddr,
		}

		outputSlice = append(outputSlice, p)
	}

	eeprom, err := e.ModuleEepromHex(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool eeprom for link='%s': %v", r.Link, err)
	} else {
		e := struct {
			ModuleEeprom string
		}{
			eeprom,
		}

		outputSlice = append(outputSlice, e)
	}

	msglvl, err := e.MsglvlGet(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool msglvl for link='%s': %v", r.Link, err)
	} else {
		g := struct {
			ModuleMsglv uint32
		}{
			msglvl,
		}

		outputSlice = append(outputSlice, g)
	}

	mapped, err := e.CmdGetMapped(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool msglvl for link='%s': %v", r.Link, err)
	} else {
		outputSlice = append(outputSlice, mapped)
	}

	c, err := e.GetChannels(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool channels for link='%s': %v", r.Link, err)
	} else {
		outputSlice = append(outputSlice, c)
	}

	cc, err := e.GetCoalesce(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool coalesce for link='%s': %v", r.Link, err)
	} else {
		outputSlice = append(outputSlice, cc)
	}

	l, err := e.LinkState(r.Link)
	if err != nil {
		log.Errorf("Failed to acquire ethtool linkstate for link='%s': %v", r.Link, err)
	} else {
		ls := struct {
			LinkState uint32
		}{
			l,
		}

		outputSlice = append(outputSlice, ls)
	}

	var outputData []string
	for _, o := range outputSlice {
		jsonData, err := json.MarshalIndent(o, "", "    ")
		if err != nil {
			log.Errorf("Failed to convert in json for link='%s': %v", r.Link, err.Error())
			return err
		}
		outputData = append(outputData, string(jsonData))
	}

	return web.JSONResponse(outputData, w)
}

func (r *Ethtool) AcquireActionEthTool(w http.ResponseWriter) error {
	_, err := netlink.LinkByName(r.Link)
	if err != nil {
		log.Errorf("Failed to find link='%s': %v", r.Link, err)
		return err
	}

	e, err := ethtool.NewEthtool()
	if err != nil {
		log.Errorf("Failed to init ethtool for link='%s': %v", r.Link, err)
		return err
	}
	defer e.Close()

	switch r.Action {
	case "statistics":
		stats, err := e.Stats(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool statitics for link='%s': %v", r.Link, err)
			return err
		}

		return web.JSONResponse(stats, w)

	case "features":
		features, err := e.Features(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool features for link='%s': %v", r.Link, err)
			return err
		}

		return web.JSONResponse(features, w)

	case "bus":
		bus, err := e.BusInfo(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool bus for link='%s': %v", r.Link, err)
			return err
		}

		b := struct {
			Bus string
		}{
			bus,
		}

		return web.JSONResponse(b, w)

	case "drivername":
		driver, err := e.DriverName(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool driver name for link='%s': %v", r.Link, err)
			return err
		}

		d := struct {
			Driver string
		}{
			driver,
		}

		return web.JSONResponse(d, w)

	case "driverinfo":
		d, err := e.DriverInfo(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool driver name for link='%s': %v", r.Link, err)
			return err
		}

		return web.JSONResponse(d, w)

	case "permaddr":
		permaddr, err := e.PermAddr(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool Perm Addr for link='%s': %v", r.Link, err)
			return err
		}

		p := struct {
			PermAddr string
		}{
			permaddr,
		}

		return web.JSONResponse(p, w)

	case "eeprom":
		eeprom, err := e.ModuleEepromHex(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool eeprom for link='%s': %v", r.Link, err)
			return err
		}

		e := struct {
			ModuleEeprom string
		}{
			eeprom,
		}

		return web.JSONResponse(e, w)

	case "msglvl":
		msglvl, err := e.MsglvlGet(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool msglvl for link='%s': %v", r.Link, err)
			return err
		}

		g := struct {
			ModuleMsglv uint32
		}{
			msglvl,
		}

		return web.JSONResponse(g, w)

	case "mapped":
		mapped, err := e.CmdGetMapped(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool msglvl for link='%s': %v", r.Link, err)
			return err
		}

		return web.JSONResponse(mapped, w)

	case "channels":
		c, err := e.GetChannels(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool channels for link='%s': %v", r.Link, err)
			return err
		}

		return web.JSONResponse(c, w)

	case "coalesce":
		c, err := e.GetCoalesce(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool coalesce for link='%s': %v", r.Link, err)
			return err
		}

		return web.JSONResponse(c, w)

	case "linkstate":
		c, err := e.LinkState(r.Link)
		if err != nil {
			log.Errorf("Failed to acquire ethtool linkstate for link='%s': %v", r.Link, err)
			return err
		}

		g := struct {
			LinkState uint32
		}{
			c,
		}

		return web.JSONResponse(g, w)
	}

	return nil
}

func (r *Ethtool) ConfigureEthTool(w http.ResponseWriter) error {
	_, err := netlink.LinkByName(r.Link)
	if err != nil {
		log.Errorf("Failed to find link='%s': %v", r.Link, err)
		return err
	}

	e, err := ethtool.NewEthtool()
	if err != nil {
		log.Errorf("Failed to init ethtool for link='%s': %v", r.Link, err)
		return err
	}
	defer e.Close()

	switch r.Action {
	case "setfeature":
		feature := make(map[string]bool)

		b, err := parser.ParseBool(r.Value)
		if err != nil {
			return err
		}

		feature[r.Property] = b
		if err := e.Change(r.Link, feature); err != nil {
			return err
		}
	}

	return nil
}
