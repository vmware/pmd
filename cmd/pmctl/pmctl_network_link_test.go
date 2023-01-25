// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/vmware/pmd/pkg/configfile"
	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/network/networkd"
	"github.com/vishvananda/netlink"
)

func configureLink(t *testing.T, l networkd.Link) (*configfile.Meta, error) {
	var resp []byte
	var err error
	resp, err = web.DispatchSocket(http.MethodPost, "", "/api/v1/network/networkd/link/configure", nil, l)
	if err != nil {
		t.Fatalf("Failed to configure Link: %v\n", err)
	}

	j := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &j); err != nil {
		t.Fatalf("Failed to decode json message: %v\n", err)
	}
	if !j.Success {
		t.Fatalf("Failed to configure Link: %v\n", j.Errors)
	}

	time.Sleep(time.Second * 3)
	m, err := networkd.CreateOrParseLinkFile("test99")
	defer os.Remove(m.Path)

	return m, err
}

func TestLink(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                       "test99",
		Alias:                      "ifalias",
		Description:                "linkconfig",
		MTUBytes:                   "10M",
		BitsPerSecond:              "1024",
		Duplex:                     "full",
		AutoNegotiation:            "no",
		WakeOnLan:                  []string{"phy", "unicast"},
		WakeOnLanPassword:          "cb:a9:87:65:43:21",
		Port:                       "mii",
		Advertise:                  []string{"10baset-half", "10baset-full"},
		LargeReceiveOffload:        "yes",
		NTupleFilter:               "no",
		StatisticsBlockCoalesceSec: 1024,
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link: %v\n", err)
	}

	if m.GetKeySectionString("Link", "Alias") != "ifalias" {
		t.Fatalf("Failed to set Alias")
	}
	if m.GetKeySectionString("Link", "Description") != "linkconfig" {
		t.Fatalf("Failed to set Description")
	}
	if m.GetKeySectionString("Link", "MTUBytes") != "10M" {
		t.Fatalf("Failed to set MTUBytes")
	}
	if m.GetKeySectionString("Link", "BitsPerSecond") != "1024" {
		t.Fatalf("Failed to set BitsPerSecond")
	}
	if m.GetKeySectionString("Link", "Duplex") != "full" {
		t.Fatalf("Failed to set Duplex")
	}
	if m.GetKeySectionString("Link", "AutoNegotiation") != "no" {
		t.Fatalf("Failed to set AutoNegotiation")
	}
	if m.GetKeySectionString("Link", "WakeOnLan") != "phy unicast" {
		t.Fatalf("Failed to set WakeOnLan")
	}
	if m.GetKeySectionString("Link", "WakeOnLanPassword") != "cb:a9:87:65:43:21" {
		t.Fatalf("Failed to set WakeOnLanPassword")
	}
	if m.GetKeySectionString("Link", "Port") != "mii" {
		t.Fatalf("Failed to set Port")
	}
	if m.GetKeySectionString("Link", "Advertise") != "10baset-half 10baset-full" {
		t.Fatalf("Failed to set Advertise")
	}
	if m.GetKeySectionString("Link", "LargeReceiveOffload") != "yes" {
		t.Fatalf("Failed to set LargeReceiveOffload")
	}
	if m.GetKeySectionString("Link", "NTupleFilter") != "no" {
		t.Fatalf("Failed to set NTupleFilter")
	}
	if m.GetKeySectionString("Link", "StatisticsBlockCoalesceSec") != "1024" {
		t.Fatalf("Failed to set Advertise")
	}
}

func TestLinkMACAddress(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:             "test99",
		MACAddressPolicy: "none",
		MACAddress:       "00:a0:de:63:7a:e6",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link MACAddress: %v\n", err)
	}

	if m.GetKeySectionString("Link", "MACAddressPolicy") != "none" {
		t.Fatalf("Failed to set MACAddressPolicy")
	}
	if m.GetKeySectionString("Link", "MACAddress") != "00:a0:de:63:7a:e6" {
		t.Fatalf("Failed to set MACAddress")
	}
}

func TestLinkName(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:       "test99",
		NamePolicy: []string{"mac", "kernel", "database", "onboard", "keep", "slot", "path"},
		Name:       "demo0",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link Name: %v\n", err)
	}

	if m.GetKeySectionString("Link", "NamePolicy") != "mac kernel database onboard keep slot path" {
		t.Fatalf("Failed to set NamePolicy")
	}
	if m.GetKeySectionString("Link", "Name") != "demo0" {
		t.Fatalf("Failed to set Name")
	}
}

func TestLinkAltName(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                   "test99",
		AlternativeNamesPolicy: []string{"mac", "database", "onboard", "slot", "path"},
		AlternativeName:        "demo0",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link AlternativeName: %v\n", err)
	}

	if m.GetKeySectionString("Link", "AlternativeNamesPolicy") != "mac database onboard slot path" {
		t.Fatalf("Failed to set AlternativeNamesPolicy")
	}
	if m.GetKeySectionString("Link", "AlternativeName") != "demo0" {
		t.Fatalf("Failed to set AlternativeName")
	}
}

func TestLinkCksumOffload(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                    "test99",
		ReceiveChecksumOffload:  "yes",
		TransmitChecksumOffload: "yes",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link ChecksumOffload: %v\n", err)
	}

	if m.GetKeySectionString("Link", "ReceiveChecksumOffload") != "yes" {
		t.Fatalf("Failed to set ReceiveChecksumOffload")
	}
	if m.GetKeySectionString("Link", "TransmitChecksumOffload") != "yes" {
		t.Fatalf("Failed to set TransmitChecksumOffload")
	}
}

func TestLinkTCPOffload(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                    "test99",
		TCPSegmentationOffload:  "yes",
		TCP6SegmentationOffload: "no",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link TCPOffload: %v\n", err)
	}

	if m.GetKeySectionString("Link", "TCPSegmentationOffload") != "yes" {
		t.Fatalf("Failed to set TCPSegmentationOffload")
	}
	if m.GetKeySectionString("Link", "TCP6SegmentationOffload") != "no" {
		t.Fatalf("Failed to set TCP6SegmentationOffload")
	}
}

func TestLinkGenericOffload(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                             "test99",
		GenericSegmentationOffload:       "yes",
		GenericReceiveOffload:            "yes",
		GenericReceiveOffloadHardware:    "no",
		GenericSegmentOffloadMaxBytes:    65536,
		GenericSegmentOffloadMaxSegments: 65535,
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link GenericOffload: %v\n", err)
	}

	if m.GetKeySectionString("Link", "GenericSegmentationOffload") != "yes" {
		t.Fatalf("Failed to set GenericSegmentationOffload")
	}
	if m.GetKeySectionString("Link", "GenericReceiveOffload") != "yes" {
		t.Fatalf("Failed to set GenericReceiveOffload")
	}
	if m.GetKeySectionString("Link", "GenericReceiveOffloadHardware") != "no" {
		t.Fatalf("Failed to set GenericReceiveOffloadHardware")
	}
	if m.GetKeySectionString("Link", "GenericSegmentOffloadMaxBytes") != "65536" {
		t.Fatalf("Failed to set GenericSegmentOffloadMaxBytes")
	}
	if m.GetKeySectionString("Link", "GenericSegmentOffloadMaxSegments") != "65535" {
		t.Fatalf("Failed to set GenericSegmentOffloadMaxSegments")
	}
}

func TestLinkVLANTags(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                                 "test99",
		ReceiveVLANCTAGHardwareAcceleration:  "yes",
		TransmitVLANCTAGHardwareAcceleration: "no",
		ReceiveVLANCTAGFilter:                "yes",
		TransmitVLANSTAGHardwareAcceleration: "yes",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link VLANTags: %v\n", err)
	}

	if m.GetKeySectionString("Link", "ReceiveVLANCTAGHardwareAcceleration") != "yes" {
		t.Fatalf("Failed to set ReceiveVLANCTAGHardwareAcceleration")
	}
	if m.GetKeySectionString("Link", "TransmitVLANCTAGHardwareAcceleration") != "no" {
		t.Fatalf("Failed to set TransmitVLANCTAGHardwareAcceleration")
	}
	if m.GetKeySectionString("Link", "ReceiveVLANCTAGFilter") != "yes" {
		t.Fatalf("Failed to set ReceiveVLANCTAGFilter")
	}
	if m.GetKeySectionString("Link", "TransmitVLANSTAGHardwareAcceleration") != "yes" {
		t.Fatalf("Failed to set TransmitVLANSTAGHardwareAcceleration")
	}
}

func TestLinkChannels(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:             "test99",
		RxChannels:       "1024",
		TxChannels:       "2045",
		OtherChannels:    "45678",
		CombinedChannels: "32456",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link Channels: %v\n", err)
	}

	if m.GetKeySectionString("Link", "RxChannels") != "1024" {
		t.Fatalf("Failed to set RxChannels")
	}
	if m.GetKeySectionString("Link", "TxChannels") != "2045" {
		t.Fatalf("Failed to set TxChannels")
	}
	if m.GetKeySectionString("Link", "OtherChannels") != "45678" {
		t.Fatalf("Failed to set OtherChannels")
	}
	if m.GetKeySectionString("Link", "CombinedChannels") != "32456" {
		t.Fatalf("Failed to set CombinedChannels")
	}
}

func TestLinkBuffer(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:              "test99",
		RxBufferSize:      "100009",
		RxMiniBufferSize:  "1998",
		RxJumboBufferSize: "10999888",
		TxBufferSize:      "83724",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link Buffer: %v\n", err)
	}

	if m.GetKeySectionString("Link", "RxBufferSize") != "100009" {
		t.Fatalf("Failed to set RxBufferSize")
	}
	if m.GetKeySectionString("Link", "RxMiniBufferSize") != "1998" {
		t.Fatalf("Failed to set RxMiniBufferSize")
	}
	if m.GetKeySectionString("Link", "RxJumboBufferSize") != "10999888" {
		t.Fatalf("Failed to set RxJumboBufferSize")
	}
	if m.GetKeySectionString("Link", "TxBufferSize") != "83724" {
		t.Fatalf("Failed to set TxBufferSize")
	}
}

func TestLinkQueues(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                "test99",
		TransmitQueues:      4096,
		ReceiveQueues:       4096,
		TransmitQueueLength: 4294967294,
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link Queues: %v\n", err)
	}

	if m.GetKeySectionString("Link", "TransmitQueues") != "4096" {
		t.Fatalf("Failed to set TransmitQueues")
	}
	if m.GetKeySectionString("Link", "ReceiveQueues") != "4096" {
		t.Fatalf("Failed to set ReceiveQueues")
	}
	if m.GetKeySectionString("Link", "TransmitQueueLength") != "4294967294" {
		t.Fatalf("Failed to set TransmitQueueLength")
	}
}

func TestLinkFlowControl(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                       "test99",
		RxFlowControl:              "yes",
		TxFlowControl:              "yes",
		AutoNegotiationFlowControl: "no",
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link FlowControl: %v\n", err)
	}

	if m.GetKeySectionString("Link", "RxFlowControl") != "yes" {
		t.Fatalf("Failed to set RxFlowControl")
	}
	if m.GetKeySectionString("Link", "TxFlowControl") != "yes" {
		t.Fatalf("Failed to set TxFlowControl")
	}
	if m.GetKeySectionString("Link", "AutoNegotiationFlowControl") != "no" {
		t.Fatalf("Failed to set AutoNegotiationFlowControl")
	}
}

func TestLinkCoalesce(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                  "test99",
		UseAdaptiveRxCoalesce: "yes",
		UseAdaptiveTxCoalesce: "yes",
		RxCoalesceSec:         23,
		RxCoalesceIrqSec:      56,
		RxCoalesceLowSec:      5,
		RxCoalesceHighSec:     76788,
		TxCoalesceSec:         23,
		TxCoalesceIrqSec:      56,
		TxCoalesceLowSec:      5,
		TxCoalesceHighSec:     76788,
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link Coalesce: %v\n", err)
	}

	if m.GetKeySectionString("Link", "UseAdaptiveRxCoalesce") != "yes" {
		t.Fatalf("Failed to set UseAdaptiveRxCoalesce")
	}
	if m.GetKeySectionString("Link", "UseAdaptiveTxCoalesce") != "yes" {
		t.Fatalf("Failed to set UseAdaptiveTxCoalesce")
	}
	if m.GetKeySectionString("Link", "RxCoalesceSec") != "23" {
		t.Fatalf("Failed to set RxCoalesceSec")
	}
	if m.GetKeySectionString("Link", "RxCoalesceIrqSec") != "56" {
		t.Fatalf("Failed to set RxCoalesceIrqSec")
	}
	if m.GetKeySectionString("Link", "RxCoalesceLowSec") != "5" {
		t.Fatalf("Failed to set RxCoalesceLowSec")
	}
	if m.GetKeySectionString("Link", "RxCoalesceHighSec") != "76788" {
		t.Fatalf("Failed to set RxCoalesceHighSec")
	}
	if m.GetKeySectionString("Link", "TxCoalesceSec") != "23" {
		t.Fatalf("Failed to set TxCoalesceSec")
	}
	if m.GetKeySectionString("Link", "TxCoalesceIrqSec") != "56" {
		t.Fatalf("Failed to set TxCoalesceIrqSec")
	}
	if m.GetKeySectionString("Link", "TxCoalesceLowSec") != "5" {
		t.Fatalf("Failed to set TxCoalesceLowSec")
	}
	if m.GetKeySectionString("Link", "TxCoalesceHighSec") != "76788" {
		t.Fatalf("Failed to set TxCoalesceHighSec")
	}
}

func TestLinkCoalescedFrames(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                     "test99",
		RxMaxCoalescedFrames:     23,
		RxMaxCoalescedIrqFrames:  56,
		RxMaxCoalescedLowFrames:  5,
		RxMaxCoalescedHighFrames: 76788,
		TxMaxCoalescedFrames:     23,
		TxMaxCoalescedIrqFrames:  56,
		TxMaxCoalescedLowFrames:  5,
		TxMaxCoalescedHighFrames: 76788,
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link CoalescedFrames: %v\n", err)
	}

	if m.GetKeySectionString("Link", "RxMaxCoalescedFrames") != "23" {
		t.Fatalf("Failed to set RxMaxCoalescedFrames")
	}
	if m.GetKeySectionString("Link", "RxMaxCoalescedIrqFrames") != "56" {
		t.Fatalf("Failed to set RxMaxCoalescedIrqFrames")
	}
	if m.GetKeySectionString("Link", "RxMaxCoalescedLowFrames") != "5" {
		t.Fatalf("Failed to set RxMaxCoalescedLowFrames")
	}
	if m.GetKeySectionString("Link", "RxMaxCoalescedHighFrames") != "76788" {
		t.Fatalf("Failed to set RxMaxCoalescedHighFrames")
	}
	if m.GetKeySectionString("Link", "TxMaxCoalescedFrames") != "23" {
		t.Fatalf("Failed to set TxMaxCoalescedFrames")
	}
	if m.GetKeySectionString("Link", "TxMaxCoalescedIrqFrames") != "56" {
		t.Fatalf("Failed to set TxMaxCoalescedIrqFrames")
	}
	if m.GetKeySectionString("Link", "TxMaxCoalescedLowFrames") != "5" {
		t.Fatalf("Failed to set TxMaxCoalescedLowFrames")
	}
	if m.GetKeySectionString("Link", "TxMaxCoalescedHighFrames") != "76788" {
		t.Fatalf("Failed to set TxMaxCoalescedHighFrames")
	}
}

func TestLinkPacketRate(t *testing.T) {
	setupLink(t, &netlink.Dummy{netlink.LinkAttrs{Name: "test99"}})
	defer removeLink(t, "test99")

	system.ExecRun("systemctl", "restart", "systemd-networkd")
	time.Sleep(time.Second * 3)

	l := networkd.Link{
		Link:                                "test99",
		CoalescePacketRateLow:               1000,
		CoalescePacketRateHigh:              32456,
		CoalescePacketRateSampleIntervalSec: 102,
	}

	m, err := configureLink(t, l)
	if err != nil {
		t.Fatalf("Failed to configure Link PacketRate: %v\n", err)
	}

	if m.GetKeySectionString("Link", "CoalescePacketRateLow") != "1000" {
		t.Fatalf("Failed to set CoalescePacketRateLow")
	}
	if m.GetKeySectionString("Link", "CoalescePacketRateHigh") != "32456" {
		t.Fatalf("Failed to set CoalescePacketRateHigh")
	}
	if m.GetKeySectionString("Link", "CoalescePacketRateSampleIntervalSec") != "102" {
		t.Fatalf("Failed to set CoalescePacketRateSampleIntervalSec")
	}
}
