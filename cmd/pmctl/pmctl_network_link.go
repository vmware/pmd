//  SPDX-License-Identifier: Apache-2.0
//  Copyright 2023 VMware, Inc.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/network/networkd"
	"github.com/urfave/cli/v2"
)

func dispatchNetworkLinkConfigReq(l networkd.Link, host string, token map[string]string) {
	if validator.IsEmpty(l.Link) {
		fmt.Printf("Failed to set link. Missing link name")
		return
	}

	resp, err := web.DispatchSocket(http.MethodPost, host, "/api/v1/network/networkd/link/configure", token, l)
	if err != nil {
		fmt.Printf("Failed to set link: %v\n", err)
		return
	}

	m := web.JSONResponseMessage{}
	if err := json.Unmarshal(resp, &m); err != nil {
		fmt.Printf("Failed to decode json message: %v\n", err)
		return
	}

	if !m.Success {
		fmt.Printf("Failed to set link: %v\n", m.Errors)
	}
}

func networkConfigureLinkMAC(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "macpolicy":
			if !validator.IsLinkMACAddressPolicy(argStrings[i+1]) {
				fmt.Printf("Failed to set link macpolicy: Invalid macpolicy=%s\n", argStrings[i+1])
				return
			}
			l.MACAddressPolicy = argStrings[i+1]
		case "macaddr":
			if validator.IsNotMAC(argStrings[i+1]) {
				fmt.Printf("Failed to set link macaddr: Invalid macaddr=%s\n", argStrings[i+1])
				return
			}
			l.MACAddress = argStrings[i+1]
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkName(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "namepolicy":
			names := strings.Split(argStrings[i+1], ",")
			for _, name := range names {
				if !validator.IsLinkNamePolicy(name) {
					fmt.Printf("Failed to set link namepolicy: Invalid namepolicy=%s\n", name)
					return
				}
			}
			l.NamePolicy = names
		case "name":
			if !validator.IsLinkName(argStrings[i+1]) {
				fmt.Printf("Failed to set link name: Invalid name=%s\n", argStrings[i+1])
				return
			}
			l.Name = argStrings[i+1]
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkAltName(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "altnamespolicy":
			altnames := strings.Split(argStrings[i+1], ",")
			for _, altname := range altnames {
				if !validator.IsLinkAlternativeNamesPolicy(altname) {
					fmt.Printf("Failed to set link altnamespolicy: Invalid altnamespolicy=%s\n", altname)
					return
				}
			}
			l.AlternativeNamesPolicy = altnames
		case "altname":
			l.AlternativeName = argStrings[i+1]
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkQueue(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "txq":
			if !validator.IsLinkQueue(argStrings[i+1]) {
				fmt.Printf("Failed to set link txq: Invalid txq=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TransmitQueues = uint(n)
		case "rxq":
			if !validator.IsLinkQueue(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxq: Invalid rxq=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.ReceiveQueues = uint(n)
		case "txqlen":
			if !validator.IsLinkQueueLength(argStrings[i+1]) {
				fmt.Printf("Failed to set link txqlen: Invalid txqlen=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TransmitQueueLength = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkChecksumOffload(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxco":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxco: Invalid rxco=%s\n", argStrings[i+1])
				return
			}
			l.ReceiveChecksumOffload = validator.BoolToString(argStrings[i+1])
		case "txco":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link txco: Invalid txco=%s\n", argStrings[i+1])
				return
			}
			l.TransmitChecksumOffload = validator.BoolToString(argStrings[i+1])
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkTCPOffload(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "tcpso":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link tcpsgmtold: Invalid tcpsgmtold=%s\n", argStrings[i+1])
				return
			}
			l.TCPSegmentationOffload = validator.BoolToString(argStrings[i+1])
		case "tcp6so":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link tcp6sgmtold: Invalid tcp6sgmtold=%s\n", argStrings[i+1])
				return
			}
			l.TCP6SegmentationOffload = validator.BoolToString(argStrings[i+1])
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkGenericOffload(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "gso":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link gso: Invalid gso=%s\n", argStrings[i+1])
				return
			}
			l.GenericSegmentationOffload = validator.BoolToString(argStrings[i+1])
		case "gro":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link gro: Invalid gro=%s\n", argStrings[i+1])
				return
			}
			l.GenericReceiveOffload = validator.BoolToString(argStrings[i+1])
		case "grohw":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link grohw: Invalid grohw=%s\n", argStrings[i+1])
				return
			}
			l.GenericReceiveOffloadHardware = validator.BoolToString(argStrings[i+1])
		case "gsomaxbytes":
			if !validator.IsLinkGSO(argStrings[i+1]) {
				fmt.Printf("Failed to set link gsomaxbytes: Invalid gsomaxbytes=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.GenericSegmentOffloadMaxBytes = uint(n)
		case "gsomaxseg":
			if !validator.IsLinkGSO(argStrings[i+1]) {
				fmt.Printf("Failed to set link gsomaxseg: Invalid gsomaxseg=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.GenericSegmentOffloadMaxSegments = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkVLANTags(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxvlanctaghwacl":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxvlanctaghwacl: Invalid rxvlanctaghwacl=%s\n", argStrings[i+1])
				return
			}
			l.ReceiveVLANCTAGHardwareAcceleration = validator.BoolToString(argStrings[i+1])
		case "txvlanctaghwacl":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link txvlanctaghwacl: Invalid txvlanctaghwacl=%s\n", argStrings[i+1])
				return
			}
			l.TransmitVLANCTAGHardwareAcceleration = validator.BoolToString(argStrings[i+1])
		case "rxvlanctagfilter":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxvlanctagfilter: Invalid rxvlanctagfilter=%s\n", argStrings[i+1])
				return
			}
			l.ReceiveVLANCTAGFilter = validator.BoolToString(argStrings[i+1])
		case "txvlanstaghwacl":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link txvlanstaghwacl: Invalid txvlanstaghwacl=%s\n", argStrings[i+1])
				return
			}
			l.TransmitVLANSTAGHardwareAcceleration = validator.BoolToString(argStrings[i+1])
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkChannel(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxch":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxch: Invalid rxch=%s\n", argStrings[i+1])
				return
			}
			l.RxChannels = argStrings[i+1]
		case "txch":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txch: Invalid txch=%s\n", argStrings[i+1])
				return
			}
			l.TxChannels = argStrings[i+1]
		case "och":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link och: Invalid och=%s\n", argStrings[i+1])
				return
			}
			l.OtherChannels = argStrings[i+1]
		case "coch":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link coch: Invalid coch=%s\n", argStrings[i+1])
				return
			}
			l.CombinedChannels = argStrings[i+1]
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkBuffer(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxbufsz":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxbufsz: Invalid rxbufsz=%s\n", argStrings[i+1])
				return
			}
			l.RxBufferSize = argStrings[i+1]
		case "rxmbufsz":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxmbufsz: Invalid rxmbufsz=%s\n", argStrings[i+1])
				return
			}
			l.RxMiniBufferSize = argStrings[i+1]
		case "rxjbufsz":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxjbufsz: Invalid rxjbufsz=%s\n", argStrings[i+1])
				return
			}
			l.RxJumboBufferSize = argStrings[i+1]
		case "txbufsz":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txbufsz: Invalid txbufsz=%s\n", argStrings[i+1])
				return
			}
			l.TxBufferSize = argStrings[i+1]
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkFlowControl(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxfctrl":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxfctrl: Invalid rxfctrl=%s\n", argStrings[i+1])
				return
			}
			l.RxFlowControl = validator.BoolToString(argStrings[i+1])
		case "txfctrl":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link txfctrl: Invalid txfctrl=%s\n", argStrings[i+1])
				return
			}
			l.TxFlowControl = validator.BoolToString(argStrings[i+1])
		case "anfctrl":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link anfctrl: Invalid anfctrl=%s\n", argStrings[i+1])
				return
			}
			l.AutoNegotiationFlowControl = validator.BoolToString(argStrings[i+1])
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkAdaptiveCoalesce(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "uarxc":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link uarxc: Invalid uarxc=%s\n", argStrings[i+1])
				return
			}
			l.UseAdaptiveRxCoalesce = validator.BoolToString(argStrings[i+1])
		case "uatxc":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link uatxc: Invalid uatxc=%s\n", argStrings[i+1])
				return
			}
			l.UseAdaptiveTxCoalesce = validator.BoolToString(argStrings[i+1])
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkRxCoalesce(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxcs":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxcs: Invalid rxcs=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxCoalesceSec = uint(n)
		case "rxcsirq":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxcsirq: Invalid rxcsirq=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxCoalesceIrqSec = uint(n)
		case "rxcslow":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxcslow: Invalid rxcslow=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxCoalesceLowSec = uint(n)
		case "rxcshigh":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxcshigh: Invalid rxcshigh=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxCoalesceHighSec = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkTxCoalesce(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "txcs":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txcs: Invalid txcs=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxCoalesceSec = uint(n)
		case "txcsirq":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txcsirq: Invalid txcsirq=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxCoalesceIrqSec = uint(n)
		case "txcslow":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txcslow: Invalid txcslow=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxCoalesceLowSec = uint(n)
		case "txcshigh":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txcshigh: Invalid txcshigh=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxCoalesceHighSec = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkRxCoalescedFrames(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "rxmcf":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxmcf: Invalid rxmcf=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxMaxCoalescedFrames = uint(n)
		case "rxmcfirq":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxmcfirq: Invalid rxmcfirq=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxMaxCoalescedIrqFrames = uint(n)
		case "rxmcflow":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxmcflow: Invalid rxmcflow=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxMaxCoalescedLowFrames = uint(n)
		case "rxmcfhigh":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link rxmcfhigh: Invalid rxmcfhigh=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.RxMaxCoalescedHighFrames = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkTxCoalescedFrames(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "txmcf":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txmcf: Invalid txmcf=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxMaxCoalescedFrames = uint(n)
		case "txmcfirq":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txmcfirq: Invalid txmcfirq=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxMaxCoalescedIrqFrames = uint(n)
		case "txmcflow":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txmcflow: Invalid txmcflow=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxMaxCoalescedLowFrames = uint(n)
		case "txmcfhigh":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link txmcfhigh: Invalid txmcfhigh=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.TxMaxCoalescedHighFrames = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLinkCoalescePacketRate(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "cprlow":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link cprlow: Invalid cprlow=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.CoalescePacketRateLow = uint(n)
		case "cprhigh":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link cprhigh: Invalid cprhigh=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.CoalescePacketRateHigh = uint(n)
		case "cprsis":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link cprsis: Invalid cprsis=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.CoalescePacketRateSampleIntervalSec = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}

func networkConfigureLink(args cli.Args, host string, token map[string]string) {
	argStrings := args.Slice()

	l := networkd.Link{}
	for i := 0; i < len(argStrings); {
		switch argStrings[i] {
		case "dev":
			l.Link = argStrings[i+1]
		case "alias":
			l.Alias = argStrings[i+1]
		case "desc":
			l.Description = argStrings[i+1]
		case "mtub":
			if !validator.IsLinkMtu(argStrings[i+1]) {
				fmt.Printf("Failed to set link mtub: Invalid mtub=%s\n", argStrings[i+1])
				return
			}
			l.MTUBytes = argStrings[i+1]
		case "bits":
			if !validator.IsLinkBitsPerSecond(argStrings[i+1]) {
				fmt.Printf("Failed to set link bits: Invalid bits=%s\n", argStrings[i+1])
				return
			}
			l.BitsPerSecond = argStrings[i+1]
		case "duplex":
			if !validator.IsLinkDuplex(argStrings[i+1]) {
				fmt.Printf("Failed to set link duplex: Invalid duplex=%s\n", argStrings[i+1])
				return
			}
			l.Duplex = argStrings[i+1]
		case "auton":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link auton: Invalid auton=%s\n", argStrings[i+1])
				return
			}
			l.AutoNegotiation = validator.BoolToString(argStrings[i+1])
		case "wol":
			lansPolicy := strings.Split(argStrings[i+1], ",")
			for _, policy := range lansPolicy {
				if !validator.IsLinkWakeOnLan(policy) {
					fmt.Printf("Failed to set link wol: Invalid wol=%s\n", policy)
					return
				}
			}
			l.WakeOnLan = lansPolicy
		case "wolpassd":
			if validator.IsNotMAC(argStrings[i+1]) {
				fmt.Printf("Failed to set link wolpassd: Invalid wolpassd=%s\n", argStrings[i+1])
				return
			}
			l.WakeOnLanPassword = argStrings[i+1]
		case "port":
			if !validator.IsLinkPort(argStrings[i+1]) {
				fmt.Printf("Failed to set link port: Invalid port=%s\n", argStrings[i+1])
				return
			}
			l.Port = argStrings[i+1]
		case "advertise":
			advList := strings.Split(argStrings[i+1], ",")
			for _, adv := range advList {
				if !validator.IsLinkAdvertise(adv) {
					fmt.Printf("Failed to set link advertise: Invalid advertise=%s\n", adv)
					return
				}
			}
			l.Advertise = advList
		case "lrxo":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link lrxo: Invalid lrxo=%s\n", argStrings[i+1])
				return
			}
			l.LargeReceiveOffload = validator.BoolToString(argStrings[i+1])
		case "ntf":
			if !validator.IsBool(argStrings[i+1]) {
				fmt.Printf("Failed to set link ntf: Invalid ntf=%s\n", argStrings[i+1])
				return
			}
			l.NTupleFilter = validator.BoolToString(argStrings[i+1])
		case "ssbcs":
			if !validator.IsUintOrMax(argStrings[i+1]) {
				fmt.Printf("Failed to set link ssbcs: Invalid ssbcs=%s\n", argStrings[i+1])
				return
			}
			n, _ := strconv.ParseUint(argStrings[i+1], 10, 32)
			l.StatisticsBlockCoalesceSec = uint(n)
		}

		i++
	}

	// Dispatch Request.
	dispatchNetworkLinkConfigReq(l, host, token)
}
