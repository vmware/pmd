// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package address

import (
	"encoding/json"
	"net/http"

	"github.com/vishvananda/netlink"
)

type Address struct {
	IP          string `json:"IP"`
	Mask        int    `json:"Mask"`
	Label       string `json:"Label"`
	Flags       int    `json:"Flags"`
	Scope       int    `json:"Scope"`
	Peer        string `json:"Peer"`
	Broadcast   string `json:"Broadcast"`
	PreferedLft int    `json:"PreferedLft"`
	ValidLft    int    `json:"ValidLft"`
}

type AddressInfo struct {
	Name      string `json:"Name"`
	Ifindex   int    `json:"Ifindex"`
	OperState string `json:"OperState"`
	Mac       string `json:"Mac"`
	MTU       int    `json:"MTU"`

	Addresses []Address `json:"Addresses"`
}

type AddressAction struct {
	Action  string  `json:"action"`
	Link    string  `json:"link"`
	Address Address `json:"Address"`
}

func decodeJSONRequest(r *http.Request) (*AddressAction, error) {
	address := AddressAction{}
	if err := json.NewDecoder(r.Body).Decode(&address); err != nil {
		return &address, err
	}

	return &address, nil
}

func (a *AddressAction) Add() error {
	link, err := netlink.LinkByName(a.Link)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(a.Address.IP)
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		return err
	}

	return nil
}

func (a *AddressAction) Remove() error {
	link, err := netlink.LinkByName(a.Link)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(a.Address.IP)
	if err != nil {
		return err
	}

	if err = netlink.AddrDel(link, addr); err != nil {
		return err
	}

	return nil
}

func fillOneAddress(a *netlink.Addr) Address {
	addr := Address{
		IP:          a.IP.String(),
		Label:       a.Label,
		Scope:       a.Scope,
		Flags:       a.Flags,
		PreferedLft: a.PreferedLft,
		ValidLft:    a.ValidLft,
	}

	addr.Mask, _ = a.Mask.Size()
	if a.Peer != nil {
		addr.Peer = a.Peer.String()
	}

	if a.Broadcast != nil {
		addr.Broadcast = a.Broadcast.String()
	}

	return addr
}

func buildAddressList(link netlink.Link, addrs []netlink.Addr) AddressInfo {
	addr := AddressInfo{
		Name:      link.Attrs().Name,
		Ifindex:   link.Attrs().Index,
		Mac:       link.Attrs().HardwareAddr.String(),
		OperState: link.Attrs().OperState.String(),
		MTU:       link.Attrs().MTU,
	}

	for _, a := range addrs {
		addr.Addresses = append(addr.Addresses, fillOneAddress(&a))
	}

	return addr
}

func AcquireAddresses() ([]AddressInfo, error) {
	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	var addrs []AddressInfo
	for _, link := range linkList {
		a, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, err
		}

		ad := buildAddressList(link, a)
		addrs = append(addrs, ad)
	}

	return addrs, nil
}
