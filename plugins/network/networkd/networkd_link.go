// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package networkd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pmd-nextgen/pkg/configfile"
	"github.com/pmd-nextgen/pkg/validator"
	"github.com/pmd-nextgen/pkg/web"
	log "github.com/sirupsen/logrus"
)

type Link struct {
	Link         string       `json:"Link"`
	MatchSection MatchSection `json:"MatchSection"`

	// [Link]
	Description                          string   `json:"Description"`
	Alias                                string   `json:"Alias"`
	MACAddressPolicy                     string   `json:"MACAddressPolicy"`
	MACAddress                           string   `json:"MACAddress"`
	NamePolicy                           []string `json:"NamePolicy"`
	Name                                 string   `json:"Name"`
	AlternativeNamesPolicy               []string `json:"AlternativeNamesPolicy"`
	AlternativeName                      string   `json:"AlternativeName"`
	TransmitQueues                       uint     `json:"TransmitQueues"`
	ReceiveQueues                        uint     `json:"ReceiveQueues"`
	TransmitQueueLength                  uint     `json:"TransmitQueueLength"`
	MTUBytes                             string   `json:"MTUBytes"`
	BitsPerSecond                        string   `json:"BitsPerSecond"`
	Duplex                               string   `json:"Duplex"`
	AutoNegotiation                      string   `json:"AutoNegotiation"`
	WakeOnLan                            []string `json:"WakeOnLan"`
	WakeOnLanPassword                    string   `json:"WakeOnLanPassword"`
	Port                                 string   `json:"Port"`
	Advertise                            []string `json:"Advertise"`
	ReceiveChecksumOffload               string   `json:"ReceiveChecksumOffload"`
	TransmitChecksumOffload              string   `json:"TransmitChecksumOffload"`
	TCPSegmentationOffload               string   `json:"TCPSegmentationOffload"`
	TCP6SegmentationOffload              string   `json:"TCP6SegmentationOffload"`
	GenericSegmentationOffload           string   `json:"GenericSegmentationOffload"`
	GenericReceiveOffload                string   `json:"GenericReceiveOffload"`
	GenericReceiveOffloadHardware        string   `json:"GenericReceiveOffloadHardware"`
	LargeReceiveOffload                  string   `json:"LargeReceiveOffload"`
	ReceiveVLANCTAGHardwareAcceleration  string   `json:"ReceiveVLANCTAGHardwareAcceleration"`
	TransmitVLANCTAGHardwareAcceleration string   `json:"TransmitVLANCTAGHardwareAcceleration"`
	ReceiveVLANCTAGFilter                string   `json:"ReceiveVLANCTAGFilter"`
	TransmitVLANSTAGHardwareAcceleration string   `json:"TransmitVLANSTAGHardwareAcceleration"`
	NTupleFilter                         string   `json:"NTupleFilter"`
	RxChannels                           string   `json:"RxChannels"`        // range 1…4294967295 or "max
	TxChannels                           string   `json:"TxChannels"`        // range 1…4294967295 or "max
	OtherChannels                        string   `json:"OtherChannels"`     // range 1…4294967295 or "max
	CombinedChannels                     string   `json:"CombinedChannels"`  // range 1…4294967295 or "max
	RxBufferSize                         string   `json:"RxBufferSize"`      // range 1…4294967295 or "max
	RxMiniBufferSize                     string   `json:"RxMiniBufferSize"`  // range 1…4294967295 or "max
	RxJumboBufferSize                    string   `json:"RxJumboBufferSize"` // range 1…4294967295 or "max
	TxBufferSize                         string   `json:"TxBufferSize"`      // range 1…4294967295 or "max
	RxFlowControl                        string   `json:"RxFlowControl"`
	TxFlowControl                        string   `json:"TxFlowControl"`
	AutoNegotiationFlowControl           string   `json:"AutoNegotiationFlowControl"`
	GenericSegmentOffloadMaxBytes        uint     `json:"GenericSegmentOffloadMaxBytes"`
	GenericSegmentOffloadMaxSegments     uint     `json:"GenericSegmentOffloadMaxSegments"`
	UseAdaptiveRxCoalesce                string   `json:"UseAdaptiveRxCoalesce"`
	UseAdaptiveTxCoalesce                string   `json:"UseAdaptiveTxCoalesce"`
	RxCoalesceSec                        uint     `json:"RxCoalesceSec"`
	RxCoalesceIrqSec                     uint     `json:"RxCoalesceIrqSec"`
	RxCoalesceLowSec                     uint     `json:"RxCoalesceLowSec"`
	RxCoalesceHighSec                    uint     `json:"RxCoalesceHighSec"`
	TxCoalesceSec                        uint     `json:"TxCoalesceSec"`
	TxCoalesceIrqSec                     uint     `json:"TxCoalesceIrqSec"`
	TxCoalesceLowSec                     uint     `json:"TxCoalesceLowSec"`
	TxCoalesceHighSec                    uint     `json:"TxCoalesceHighSec"`
	RxMaxCoalescedFrames                 uint     `json:"RxMaxCoalescedFrames"`
	RxMaxCoalescedIrqFrames              uint     `json:"RxMaxCoalescedIrqFrames"`
	RxMaxCoalescedLowFrames              uint     `json:"RxMaxCoalescedLowFrames"`
	RxMaxCoalescedHighFrames             uint     `json:"RxMaxCoalescedHighFrames"`
	TxMaxCoalescedFrames                 uint     `json:"TxMaxCoalescedFrames"`
	TxMaxCoalescedIrqFrames              uint     `json:"TxMaxCoalescedIrqFrames"`
	TxMaxCoalescedLowFrames              uint     `json:"TxMaxCoalescedLowFrames"`
	TxMaxCoalescedHighFrames             uint     `json:"TxMaxCoalescedHighFrames"`
	CoalescePacketRateLow                uint     `json:"CoalescePacketRateLow"`
	CoalescePacketRateHigh               uint     `json:"CoalescePacketRateHigh"`
	CoalescePacketRateSampleIntervalSec  uint     `json:"CoalescePacketRateSampleIntervalSec"`
	StatisticsBlockCoalesceSec           uint     `json:"StatisticsBlockCoalesceSec"`
}

func decodeLinkJSONRequest(r *http.Request) (*Link, error) {
	l := Link{}
	if err := json.NewDecoder(r.Body).Decode(&l); err != nil {
		return nil, err
	}

	return &l, nil
}

func (l *Link) BuildLinkSection(m *configfile.Meta) error {
	if !validator.IsEmpty(l.Description) {
		m.SetKeySectionString("Link", "Description", l.Description)
	}

	if !validator.IsEmpty(l.Alias) {
		m.SetKeySectionString("Link", "Alias", l.Alias)
	}

	if !validator.IsEmpty(l.MACAddressPolicy) {
		if !validator.IsLinkMACAddressPolicy(l.MACAddressPolicy) {
			log.Errorf("Failed to create .link. Invalid MACAddressPolicy='%s'", l.MACAddressPolicy)
			return fmt.Errorf("invalid MACAddressPolicy='%s'", l.MACAddressPolicy)
		}

		m.SetKeySectionString("Link", "MACAddressPolicy", l.MACAddressPolicy)
	}
	if !validator.IsEmpty(l.MACAddress) {
		if validator.IsNotMAC(l.MACAddress) {
			log.Errorf("Failed to create .link. Invalid MACAddress='%s'", l.MACAddress)
			return fmt.Errorf("invalid MACAddress='%s'", l.MACAddress)
		}

		m.SetKeySectionString("Link", "MACAddress", l.MACAddress)
	}

	if !validator.IsArrayEmpty(l.NamePolicy) {
		for _, name := range l.NamePolicy {
			if !validator.IsLinkNamePolicy(name) {
				log.Errorf("Failed to create .link. Invalid NamePolicy='%s'", name)
				return fmt.Errorf("invalid NamePolicy='%s'", name)
			}
		}
		m.SetKeySectionString("Link", "NamePolicy", strings.Join(l.NamePolicy, " "))
	}
	if !validator.IsEmpty(l.Name) {
		if !validator.IsLinkName(l.Name) {
			log.Errorf("Failed to create .link. Invalid Name='%s'", l.Name)
			return fmt.Errorf("invalid Name='%s'", l.Name)
		}

		m.SetKeySectionString("Link", "Name", l.Name)
	}

	if !validator.IsArrayEmpty(l.AlternativeNamesPolicy) {
		for _, altname := range l.AlternativeNamesPolicy {
			if !validator.IsLinkAlternativeNamesPolicy(altname) {
				log.Errorf("Failed to create .link. Invalid AlternativeNamesPolicy='%s'", altname)
				return fmt.Errorf("invalid AlternativeNamesPolicy='%s'", altname)
			}
		}
		m.SetKeySectionString("Link", "AlternativeNamesPolicy", strings.Join(l.AlternativeNamesPolicy, " "))
	}
	if !validator.IsEmpty(l.AlternativeName) {
		m.SetKeySectionString("Link", "AlternativeName", l.AlternativeName)
	}

	if l.TransmitQueues > 0 {
		m.SetKeySectionUint("Link", "TransmitQueues", l.TransmitQueues)
	}
	if l.ReceiveQueues > 0 {
		m.SetKeySectionUint("Link", "ReceiveQueues", l.ReceiveQueues)
	}
	if l.TransmitQueueLength > 0 {
		m.SetKeySectionUint("Link", "TransmitQueueLength", l.TransmitQueueLength)
	}

	if !validator.IsEmpty(l.MTUBytes) {
		if !validator.IsLinkMtu(l.MTUBytes) {
			log.Errorf("Failed to create .link. Invalid MTUBytes='%s'", l.MTUBytes)
			return fmt.Errorf("invalid MTUBytes='%s'", l.MTUBytes)
		}

		m.SetKeySectionString("Link", "MTUBytes", l.MTUBytes)
	}

	if !validator.IsEmpty(l.BitsPerSecond) {
		if !validator.IsLinkBitsPerSecond(l.BitsPerSecond) {
			log.Errorf("Failed to create .link. Invalid BitsPerSecond='%s'", l.BitsPerSecond)
			return fmt.Errorf("invalid BitsPerSecond='%s'", l.BitsPerSecond)
		}

		m.SetKeySectionString("Link", "BitsPerSecond", l.BitsPerSecond)
	}

	if !validator.IsEmpty(l.Duplex) {
		if !validator.IsLinkDuplex(l.Duplex) {
			log.Errorf("Failed to create .link. Invalid Duplex='%s'", l.Duplex)
			return fmt.Errorf("invalid Duplex='%s'", l.Duplex)
		}

		m.SetKeySectionString("Link", "Duplex", l.Duplex)
	}

	if !validator.IsEmpty(l.AutoNegotiation) {
		if !validator.IsBool(l.AutoNegotiation) {
			log.Errorf("Failed to create .link. Invalid AutoNegotiation='%s'", l.AutoNegotiation)
			return fmt.Errorf("invalid AutoNegotiation='%s'", l.AutoNegotiation)
		}

		m.SetKeySectionString("Link", "AutoNegotiation", l.AutoNegotiation)
	}

	if !validator.IsArrayEmpty(l.WakeOnLan) {
		for _, lan := range l.WakeOnLan {
			if !validator.IsLinkWakeOnLan(lan) {
				log.Errorf("Failed to create .link. Invalid WakeOnLan='%s'", lan)
				return fmt.Errorf("invalid WakeOnLan='%s'", lan)
			}
		}
		m.SetKeySectionString("Link", "WakeOnLan", strings.Join(l.WakeOnLan, " "))
	}

	if !validator.IsEmpty(l.WakeOnLanPassword) {
		if validator.IsNotMAC(l.WakeOnLanPassword) {
			log.Errorf("Failed to create .link. Invalid WakeOnLanPassword='%s'", l.WakeOnLanPassword)
			return fmt.Errorf("invalid WakeOnLanPassword='%s'", l.WakeOnLanPassword)
		}

		m.SetKeySectionString("Link", "WakeOnLanPassword", l.WakeOnLanPassword)
	}

	if !validator.IsEmpty(l.Port) {
		if !validator.IsLinkPort(l.Port) {
			log.Errorf("Failed to create .link. Invalid Port='%s'", l.Port)
			return fmt.Errorf("invalid Port='%s'", l.Port)
		}

		m.SetKeySectionString("Link", "Port", l.Port)
	}

	if !validator.IsArrayEmpty(l.Advertise) {
		for _, adv := range l.Advertise {
			if !validator.IsLinkAdvertise(adv) {
				log.Errorf("Failed to create .link. Invalid Advertise='%s'", adv)
				return fmt.Errorf("invalid Advertise='%s'", adv)
			}
		}
		m.SetKeySectionString("Link", "Advertise", strings.Join(l.Advertise, " "))
	}

	if !validator.IsEmpty(l.ReceiveChecksumOffload) {
		if !validator.IsBool(l.ReceiveChecksumOffload) {
			log.Errorf("Failed to create .link. Invalid ReceiveChecksumOffload='%s'", l.ReceiveChecksumOffload)
			return fmt.Errorf("invalid ReceiveChecksumOffload='%s'", l.ReceiveChecksumOffload)
		}

		m.SetKeySectionString("Link", "ReceiveChecksumOffload", l.ReceiveChecksumOffload)
	}
	if !validator.IsEmpty(l.TransmitChecksumOffload) {
		if !validator.IsBool(l.TransmitChecksumOffload) {
			log.Errorf("Failed to create .link. Invalid TransmitChecksumOffload='%s'", l.TransmitChecksumOffload)
			return fmt.Errorf("invalid TransmitChecksumOffload='%s'", l.TransmitChecksumOffload)
		}

		m.SetKeySectionString("Link", "TransmitChecksumOffload", l.TransmitChecksumOffload)
	}

	if !validator.IsEmpty(l.TCPSegmentationOffload) {
		if !validator.IsBool(l.TCPSegmentationOffload) {
			log.Errorf("Failed to create .link. Invalid TCPSegmentationOffload='%s'", l.TCPSegmentationOffload)
			return fmt.Errorf("invalid TCPSegmentationOffload='%s'", l.TCPSegmentationOffload)
		}

		m.SetKeySectionString("Link", "TCPSegmentationOffload", l.TCPSegmentationOffload)
	}
	if !validator.IsEmpty(l.TCP6SegmentationOffload) {
		if !validator.IsBool(l.TCP6SegmentationOffload) {
			log.Errorf("Failed to create .link. Invalid TCP6SegmentationOffload='%s'", l.TCP6SegmentationOffload)
			return fmt.Errorf("invalid TCP6SegmentationOffload='%s'", l.TCP6SegmentationOffload)
		}

		m.SetKeySectionString("Link", "TCP6SegmentationOffload", l.TCP6SegmentationOffload)
	}

	if !validator.IsEmpty(l.GenericSegmentationOffload) {
		if !validator.IsBool(l.GenericSegmentationOffload) {
			log.Errorf("Failed to create .link. Invalid GenericSegmentationOffload='%s'", l.GenericSegmentationOffload)
			return fmt.Errorf("invalid GenericSegmentationOffload='%s'", l.GenericSegmentationOffload)
		}

		m.SetKeySectionString("Link", "GenericSegmentationOffload", l.GenericSegmentationOffload)
	}
	if !validator.IsEmpty(l.GenericReceiveOffload) {
		if !validator.IsBool(l.GenericReceiveOffload) {
			log.Errorf("Failed to create .link. Invalid GenericReceiveOffload='%s'", l.GenericReceiveOffload)
			return fmt.Errorf("invalid GenericReceiveOffload='%s'", l.GenericReceiveOffload)
		}

		m.SetKeySectionString("Link", "GenericReceiveOffload", l.GenericReceiveOffload)
	}
	if !validator.IsEmpty(l.GenericReceiveOffloadHardware) {
		if !validator.IsBool(l.GenericReceiveOffloadHardware) {
			log.Errorf("Failed to create .link. Invalid GenericReceiveOffloadHardware='%s'", l.GenericReceiveOffloadHardware)
			return fmt.Errorf("invalid GenericReceiveOffloadHardware='%s'", l.GenericReceiveOffloadHardware)
		}

		m.SetKeySectionString("Link", "GenericReceiveOffloadHardware", l.GenericReceiveOffloadHardware)
	}
	if !validator.IsEmpty(l.LargeReceiveOffload) {
		if !validator.IsBool(l.LargeReceiveOffload) {
			log.Errorf("Failed to create .link. Invalid LargeReceiveOffload='%s'", l.LargeReceiveOffload)
			return fmt.Errorf("invalid LargeReceiveOffload='%s'", l.LargeReceiveOffload)
		}

		m.SetKeySectionString("Link", "LargeReceiveOffload", l.LargeReceiveOffload)
	}

	if !validator.IsEmpty(l.ReceiveVLANCTAGHardwareAcceleration) {
		if !validator.IsBool(l.ReceiveVLANCTAGHardwareAcceleration) {
			log.Errorf("Failed to create .link. Invalid ReceiveVLANCTAGHardwareAcceleration='%s'", l.ReceiveVLANCTAGHardwareAcceleration)
			return fmt.Errorf("invalid ReceiveVLANCTAGHardwareAcceleration='%s'", l.ReceiveVLANCTAGHardwareAcceleration)
		}

		m.SetKeySectionString("Link", "ReceiveVLANCTAGHardwareAcceleration", l.ReceiveVLANCTAGHardwareAcceleration)
	}
	if !validator.IsEmpty(l.TransmitVLANCTAGHardwareAcceleration) {
		if !validator.IsBool(l.TransmitVLANCTAGHardwareAcceleration) {
			log.Errorf("Failed to create .link. Invalid TransmitVLANCTAGHardwareAcceleration='%s'", l.TransmitVLANCTAGHardwareAcceleration)
			return fmt.Errorf("invalid TransmitVLANCTAGHardwareAcceleration='%s'", l.TransmitVLANCTAGHardwareAcceleration)
		}

		m.SetKeySectionString("Link", "TransmitVLANCTAGHardwareAcceleration", l.TransmitVLANCTAGHardwareAcceleration)
	}
	if !validator.IsEmpty(l.ReceiveVLANCTAGFilter) {
		if !validator.IsBool(l.ReceiveVLANCTAGFilter) {
			log.Errorf("Failed to create .link. Invalid ReceiveVLANCTAGFilter='%s'", l.ReceiveVLANCTAGFilter)
			return fmt.Errorf("invalid ReceiveVLANCTAGFilter='%s'", l.ReceiveVLANCTAGFilter)
		}

		m.SetKeySectionString("Link", "ReceiveVLANCTAGFilter", l.ReceiveVLANCTAGFilter)
	}
	if !validator.IsEmpty(l.TransmitVLANSTAGHardwareAcceleration) {
		if !validator.IsBool(l.TransmitVLANSTAGHardwareAcceleration) {
			log.Errorf("Failed to create .link. Invalid TransmitVLANSTAGHardwareAcceleration='%s'", l.TransmitVLANSTAGHardwareAcceleration)
			return fmt.Errorf("invalid TransmitVLANSTAGHardwareAcceleration='%s'", l.TransmitVLANSTAGHardwareAcceleration)
		}

		m.SetKeySectionString("Link", "TransmitVLANSTAGHardwareAcceleration", l.TransmitVLANSTAGHardwareAcceleration)
	}

	if !validator.IsEmpty(l.NTupleFilter) {
		if !validator.IsBool(l.NTupleFilter) {
			log.Errorf("Failed to create .link. Invalid NTupleFilter='%s'", l.NTupleFilter)
			return fmt.Errorf("invalid NTupleFilter='%s'", l.NTupleFilter)
		}

		m.SetKeySectionString("Link", "NTupleFilter", l.NTupleFilter)
	}

	if !validator.IsEmpty(l.RxChannels) {
		if !validator.IsUintOrMax(l.RxChannels) {
			log.Errorf("Failed to create .link. Invalid RxChannels='%s'", l.RxChannels)
			return fmt.Errorf("invalid RxChannels='%s'", l.RxChannels)
		}

		m.SetKeySectionString("Link", "RxChannels", l.RxChannels)
	}
	if !validator.IsEmpty(l.TxChannels) {
		if !validator.IsUintOrMax(l.TxChannels) {
			log.Errorf("Failed to create .link. Invalid TxChannels='%s'", l.TxChannels)
			return fmt.Errorf("invalid TxChannels='%s'", l.TxChannels)
		}

		m.SetKeySectionString("Link", "TxChannels", l.TxChannels)
	}
	if !validator.IsEmpty(l.OtherChannels) {
		if !validator.IsUintOrMax(l.OtherChannels) {
			log.Errorf("Failed to create .link. Invalid OtherChannels='%s'", l.OtherChannels)
			return fmt.Errorf("invalid OtherChannels='%s'", l.OtherChannels)
		}

		m.SetKeySectionString("Link", "OtherChannels", l.OtherChannels)
	}
	if !validator.IsEmpty(l.CombinedChannels) {
		if !validator.IsUintOrMax(l.CombinedChannels) {
			log.Errorf("Failed to create .link. Invalid CombinedChannels='%s'", l.CombinedChannels)
			return fmt.Errorf("invalid CombinedChannels='%s'", l.CombinedChannels)
		}

		m.SetKeySectionString("Link", "CombinedChannels", l.CombinedChannels)
	}

	if !validator.IsEmpty(l.RxBufferSize) {
		if !validator.IsUintOrMax(l.RxBufferSize) {
			log.Errorf("Failed to create .link. Invalid RxBufferSize='%s'", l.RxBufferSize)
			return fmt.Errorf("invalid RxBufferSize='%s'", l.RxBufferSize)
		}

		m.SetKeySectionString("Link", "RxBufferSize", l.RxBufferSize)
	}
	if !validator.IsEmpty(l.RxMiniBufferSize) {
		if !validator.IsUintOrMax(l.RxMiniBufferSize) {
			log.Errorf("Failed to create .link. Invalid RxMiniBufferSize='", l.RxMiniBufferSize)
			return fmt.Errorf("invalid RxMiniBufferSize='%s'", l.RxMiniBufferSize)
		}

		m.SetKeySectionString("Link", "RxMiniBufferSize", l.RxMiniBufferSize)
	}
	if !validator.IsEmpty(l.RxJumboBufferSize) {
		if !validator.IsUintOrMax(l.RxJumboBufferSize) {
			log.Errorf("Failed to create .link. Invalid RxJumboBufferSize='%s': %v", l.RxJumboBufferSize)
			return fmt.Errorf("invalid RxJumboBufferSize='%s'", l.RxJumboBufferSize)
		}

		m.SetKeySectionString("Link", "RxJumboBufferSize", l.RxJumboBufferSize)
	}
	if !validator.IsEmpty(l.TxBufferSize) {
		if !validator.IsUintOrMax(l.TxBufferSize) {
			log.Errorf("Failed to create .link. Invalid TxBufferSize='%s'", l.TxBufferSize)
			return fmt.Errorf("invalid TxBufferSize='%s'", l.TxBufferSize)
		}

		m.SetKeySectionString("Link", "TxBufferSize", l.TxBufferSize)
	}

	if !validator.IsEmpty(l.RxFlowControl) {
		if !validator.IsBool(l.RxFlowControl) {
			log.Errorf("Failed to create .link. Invalid RxFlowControl='%s'", l.RxFlowControl)
			return fmt.Errorf("invalid RxFlowControl='%s'", l.RxFlowControl)
		}

		m.SetKeySectionString("Link", "RxFlowControl", l.RxFlowControl)
	}
	if !validator.IsEmpty(l.TxFlowControl) {
		if !validator.IsBool(l.TxFlowControl) {
			log.Errorf("Failed to create .link. Invalid TxFlowControl='%s'", l.TxFlowControl)
			return fmt.Errorf("invalid TxFlowControl='%s'", l.TxFlowControl)
		}

		m.SetKeySectionString("Link", "TxFlowControl", l.TxFlowControl)
	}
	if !validator.IsEmpty(l.AutoNegotiationFlowControl) {
		if !validator.IsBool(l.AutoNegotiationFlowControl) {
			log.Errorf("Failed to create .link. Invalid AutoNegotiationFlowControl='%s'", l.AutoNegotiationFlowControl)
			return fmt.Errorf("invalid AutoNegotiationFlowControl='%s'", l.AutoNegotiationFlowControl)
		}

		m.SetKeySectionString("Link", "AutoNegotiationFlowControl", l.AutoNegotiationFlowControl)
	}

	if l.GenericSegmentOffloadMaxBytes > 0 {
		m.SetKeySectionUint("Link", "GenericSegmentOffloadMaxBytes", l.GenericSegmentOffloadMaxBytes)
	}
	if l.GenericSegmentOffloadMaxSegments > 0 {
		m.SetKeySectionUint("Link", "GenericSegmentOffloadMaxSegments", l.GenericSegmentOffloadMaxSegments)
	}

	if !validator.IsEmpty(l.UseAdaptiveRxCoalesce) {
		if !validator.IsBool(l.UseAdaptiveRxCoalesce) {
			log.Errorf("Failed to create .link. Invalid UseAdaptiveRxCoalesce='%s'", l.UseAdaptiveRxCoalesce)
			return fmt.Errorf("invalid UseAdaptiveRxCoalesce='%s'", l.UseAdaptiveRxCoalesce)
		}

		m.SetKeySectionString("Link", "UseAdaptiveRxCoalesce", l.UseAdaptiveRxCoalesce)
	}
	if !validator.IsEmpty(l.UseAdaptiveTxCoalesce) {
		if !validator.IsBool(l.UseAdaptiveTxCoalesce) {
			log.Errorf("Failed to create .link. Invalid UseAdaptiveTxCoalesce='%s'", l.UseAdaptiveTxCoalesce)
			return fmt.Errorf("invalid UseAdaptiveTxCoalesce='%s'", l.UseAdaptiveTxCoalesce)
		}

		m.SetKeySectionString("Link", "UseAdaptiveTxCoalesce", l.UseAdaptiveTxCoalesce)
	}

	if l.RxCoalesceSec > 0 {
		m.SetKeySectionUint("Link", "RxCoalesceSec", l.RxCoalesceSec)
	}
	if l.RxCoalesceIrqSec > 0 {
		m.SetKeySectionUint("Link", "RxCoalesceIrqSec", l.RxCoalesceIrqSec)
	}
	if l.RxCoalesceLowSec > 0 {
		m.SetKeySectionUint("Link", "RxCoalesceLowSec", l.RxCoalesceLowSec)
	}
	if l.RxCoalesceHighSec > 0 {
		m.SetKeySectionUint("Link", "RxCoalesceHighSec", l.RxCoalesceHighSec)
	}

	if l.TxCoalesceSec > 0 {
		m.SetKeySectionUint("Link", "TxCoalesceSec", l.TxCoalesceSec)
	}
	if l.TxCoalesceIrqSec > 0 {
		m.SetKeySectionUint("Link", "TxCoalesceIrqSec", l.TxCoalesceIrqSec)
	}
	if l.TxCoalesceLowSec > 0 {
		m.SetKeySectionUint("Link", "TxCoalesceLowSec", l.TxCoalesceLowSec)
	}
	if l.TxCoalesceHighSec > 0 {
		m.SetKeySectionUint("Link", "TxCoalesceHighSec", l.TxCoalesceHighSec)
	}

	if l.RxMaxCoalescedFrames > 0 {
		m.SetKeySectionUint("Link", "RxMaxCoalescedFrames", l.RxMaxCoalescedFrames)
	}
	if l.RxMaxCoalescedIrqFrames > 0 {
		m.SetKeySectionUint("Link", "RxMaxCoalescedIrqFrames", l.RxMaxCoalescedIrqFrames)
	}
	if l.RxMaxCoalescedLowFrames > 0 {
		m.SetKeySectionUint("Link", "RxMaxCoalescedLowFrames", l.RxMaxCoalescedLowFrames)
	}
	if l.RxMaxCoalescedHighFrames > 0 {
		m.SetKeySectionUint("Link", "RxMaxCoalescedHighFrames", l.RxMaxCoalescedHighFrames)
	}
	if l.TxMaxCoalescedFrames > 0 {
		m.SetKeySectionUint("Link", "TxMaxCoalescedFrames", l.TxMaxCoalescedFrames)
	}
	if l.TxMaxCoalescedIrqFrames > 0 {
		m.SetKeySectionUint("Link", "TxMaxCoalescedIrqFrames", l.TxMaxCoalescedIrqFrames)
	}
	if l.TxMaxCoalescedLowFrames > 0 {
		m.SetKeySectionUint("Link", "TxMaxCoalescedLowFrames", l.TxMaxCoalescedLowFrames)
	}
	if l.TxMaxCoalescedHighFrames > 0 {
		m.SetKeySectionUint("Link", "TxMaxCoalescedHighFrames", l.TxMaxCoalescedHighFrames)
	}

	if l.CoalescePacketRateLow > 0 {
		m.SetKeySectionUint("Link", "CoalescePacketRateLow", l.CoalescePacketRateLow)
	}
	if l.CoalescePacketRateHigh > 0 {
		m.SetKeySectionUint("Link", "CoalescePacketRateHigh", l.CoalescePacketRateHigh)
	}

	if l.CoalescePacketRateSampleIntervalSec > 0 {
		m.SetKeySectionUint("Link", "CoalescePacketRateSampleIntervalSec", l.CoalescePacketRateSampleIntervalSec)
	}
	if l.StatisticsBlockCoalesceSec > 0 {
		m.SetKeySectionUint("Link", "StatisticsBlockCoalesceSec", l.StatisticsBlockCoalesceSec)
	}

	return nil
}

func (l *Link) ConfigureLink(ctx context.Context, w http.ResponseWriter) error {
	m, err := CreateOrParseLinkFile(l.Link)
	if err != nil {
		return err
	}

	if err := l.BuildLinkSection(m); err != nil {
		return err
	}

	if err := m.Save(); err != nil {
		log.Errorf("Failed to update config file='%s': %v", m.Path, err)
		return err
	}

	c, err := NewSDConnection()
	if err != nil {
		log.Errorf("Failed to establish connection with the system bus: %v", err)
		return err
	}
	defer c.Close()

	if err := c.DBusNetworkReload(ctx); err != nil {
		return err
	}

	return web.JSONResponse("configured", w)
}
