// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package timedate

import (
	"context"
	"net/http"

	"github.com/pmd-nextgen/pkg/web"
	log "github.com/sirupsen/logrus"
)

type TimeDate struct {
	Method string `json:"Method"`
	Value  string `json:"Value"`
}

type Describe struct {
	Timezone        string `json:"Timezone"`
	LocalRTC        bool   `json:"LocalRTC"`
	CanNTP          bool   `json:"CanNTP"`
	NTP             string `json:"NTP"`
	NTPSynchronized bool   `json:"NTPSynchronized"`
	TimeUSec        uint64 `json:"TimeUSec"`
	RTCTimeUSec     uint64 `json:"RTCTimeUSec"`
}

func (t *TimeDate) ConfigureTimeDate(w http.ResponseWriter) error {
	conn, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to get systemd bus connection: %v", err)
		return err
	}
	defer conn.Close()

	err = conn.dBusConfigureTimeDate(t.Method, t.Value)
	if err != nil {
		log.Errorf("Failed to set timedate property: %s", err)
		return err
	}

	web.JSONResponse("configured", w)
	return nil
}

func AcquireTimeDate(ctx context.Context, w http.ResponseWriter) error {
	h, err := DBusAcquireTimeDate()
	if err != nil {
		return err
	}

	web.JSONResponse(h, w)
	return nil
}
