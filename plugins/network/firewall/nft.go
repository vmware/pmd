// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package firewall

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"
	"github.com/vmware/pmd/pkg/system"
	"github.com/vmware/pmd/pkg/validator"
	"github.com/vmware/pmd/pkg/web"
	"golang.org/x/sys/unix"
)

type Table struct {
	Name   string `json:"Name"`
	Family string `json:"Family"`
}

type Chain struct {
	Name     string `json:"Name"`
	Family   string `json:"Family"`
	Table    string `json:"Table"`
	Hook     string `json:"Hook"`
	Priority string `json:"Priority"`
	Type     string `json:"Type"`
	Policy   string `json:"Policy"`
}

type Nft struct {
	Table   Table    `json:"Table"`
	Chain   Chain    `json:"Chain"`
	Command []string `json:"Command"`
}

const (
	nftFilePath = "/etc/nftables-pmd-nextgen.conf"
)

func decodeNftJSONRequest(r *http.Request) (*Nft, error) {
	n := Nft{}
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		return nil, err
	}

	return &n, nil
}

func newConnection() nftables.Conn {
	return nftables.Conn{}
}

func acquireTables() ([]*nftables.Table, error) {
	c := newConnection()
	return c.ListTables()
}

func createTableMapKey(name string, family nftables.TableFamily) string {
	return name + "_" + convertToStringFamily(family)
}

func acquireChains() ([]*nftables.Chain, error) {
	c := newConnection()
	return c.ListChains()
}

func createChainMapKey(table, chain string, family nftables.TableFamily) string {
	return table + "_" + chain + "_" + convertToStringFamily(family)
}

func convertToUnixFamily(f string) nftables.TableFamily {
	var family nftables.TableFamily
	switch f {
	case "inet":
		family = unix.NFPROTO_INET
	case "ipv4":
		family = unix.NFPROTO_IPV4
	case "ipv6":
		family = unix.NFPROTO_IPV6
	case "arp":
		family = unix.NFPROTO_ARP
	case "netdev":
		family = unix.NFPROTO_NETDEV
	case "bridge":
		family = unix.NFPROTO_BRIDGE
	}

	return family
}

func convertToStringFamily(f nftables.TableFamily) string {
	var family string
	switch f {
	case unix.NFPROTO_INET:
		family = "inet"
	case unix.NFPROTO_IPV4:
		family = "ipv4"
	case unix.NFPROTO_IPV6:
		family = "ipv6"
	case unix.NFPROTO_ARP:
		family = "arp"
	case unix.NFPROTO_NETDEV:
		family = "netdev"
	case unix.NFPROTO_BRIDGE:
		family = "bridge"
	}

	return family
}

func convertToUnixHook(h string) *nftables.ChainHook {
        var hook *nftables.ChainHook
        switch h {
        case "prerouting":
                hook = nftables.ChainHookRef(unix.NF_INET_PRE_ROUTING)
        case "postrouting":
                hook = nftables.ChainHookRef(unix.NF_INET_POST_ROUTING)
        case "input":
                hook = nftables.ChainHookRef(unix.NF_INET_LOCAL_IN)
        case "output":
                hook = nftables.ChainHookRef(unix.NF_INET_LOCAL_OUT)
        case "forward":
                hook = nftables.ChainHookRef(unix.NF_INET_FORWARD)
        case "ingress":
                hook = nftables.ChainHookRef(unix.NF_NETDEV_INGRESS)
        }

        return hook
}
        
func convertToUnixPolicy(p string) *nftables.ChainPolicy {
	var policy nftables.ChainPolicy
	switch p {
	case "drop":
		policy = nftables.ChainPolicyDrop
	case "accept":
		policy = nftables.ChainPolicyAccept
	}

	return &policy
}

func getTablesAndCreateMap(tableMap map[string]*nftables.Table) error {
	tables, err := acquireTables()
	if err != nil {
		log.Errorf("Failed to acquire nft tables: %v", err)
		return err
	}

	for _, t := range tables {
		key := createTableMapKey(t.Name, t.Family)
		tableMap[key] = t
	}

	return nil
}

func getChainsAndCreateMap(chainMap map[string]*nftables.Chain) error {
	chains, err := acquireChains()
	if err != nil {
		log.Errorf("Failed to acquire nft chains: %v", err)
		return err
	}

	for _, c := range chains {
		key := createChainMapKey(c.Table.Name, c.Name, c.Table.Family)
		chainMap[key] = c
	}

	return nil
}

func (n *Nft) ParseTable(tbl *nftables.Table) error {
	if validator.IsEmpty(n.Table.Name) {
		log.Errorf("Failed to add nft table, Missing table name")
		return fmt.Errorf("missing table name")
	}
	tbl.Name = n.Table.Name

	if !validator.IsEmpty(n.Table.Family) {
		if !validator.IsNFTFamily(n.Table.Family) {
			log.Errorf("Failed to add nft table, Invalid family")
			return fmt.Errorf("Invalid family")
		}
	} else {
		n.Table.Family = "ipv4"
	}
	tbl.Family = convertToUnixFamily(n.Table.Family)

	return nil
}

func (n *Nft) AddTable(w http.ResponseWriter) error {
	tbl := nftables.Table{}
	if err := n.ParseTable(&tbl); err != nil {
		log.Errorf("Failed to parse table: %v", err)
		return err
	}

	c := newConnection()

	c.AddTable(&tbl)

	if err := c.Flush(); err != nil {
		log.Errorf("Unable to flush connection: %v", err)
		return err
	}

	return web.JSONResponse("added", w)
}

func (n *Nft) RemoveTable(w http.ResponseWriter) error {
	tbl := nftables.Table{}
	if err := n.ParseTable(&tbl); err != nil {
		log.Errorf("Failed to parse table: %v", err)
		return err
	}

	c := newConnection()

	c.DelTable(&tbl)

	if err := c.Flush(); err != nil {
		log.Errorf("Unable to flush connection: %v", err)
		return err
	}

	return web.JSONResponse("removed", w)
}

func (n *Nft) ShowTable(w http.ResponseWriter) error {
	tableMap := make(map[string]*nftables.Table)
	if err := getTablesAndCreateMap(tableMap); err != nil {
		log.Errorf("Failed to get nft tables: %v", err)
		return fmt.Errorf("failed to get nft tables: %v", err)
	}

	if !validator.IsEmpty(n.Table.Name) && !validator.IsEmpty(n.Table.Family) {
		key := createTableMapKey(n.Table.Name, convertToUnixFamily(n.Table.Family))
		v, ok := tableMap[key]
		if !ok {
			return fmt.Errorf("Table not found='%s'", n.Table.Name)
		}
		result := make(map[string]*nftables.Table)
		result[n.Table.Name] = v
		return web.JSONResponse(result, w)
	}

	return web.JSONResponse(tableMap, w)
}

func (n *Nft) ParseChain(ch *nftables.Chain) error {
	if validator.IsEmpty(n.Chain.Name) {
		log.Errorf("Failed to add nft chain, Missing chain name")
		return fmt.Errorf("missing chain name")
	}
	ch.Name = n.Chain.Name

	if validator.IsEmpty(n.Chain.Table) {
		log.Errorf("Failed to add nft chain, Missing table name")
		return fmt.Errorf("missing table name")
	}

	if !validator.IsEmpty(n.Chain.Family) {
		if !validator.IsNFTFamily(n.Chain.Family) {
			log.Errorf("Failed to add nft chain, Invalid family")
			return fmt.Errorf("invalid family: '%s'", n.Chain.Family)
		}
	} else {
		n.Chain.Family = "ipv4"
	}

	if !validator.IsEmpty(n.Chain.Hook) {
		if !validator.IsNFTChainHook(n.Chain.Hook) {
			log.Errorf("Failed to add nft chain, Invalid hook")
			return fmt.Errorf("invalid hook: '%s'", n.Chain.Hook)
		}
		ch.Hooknum = convertToUnixHook(n.Chain.Hook)
	}

	if !validator.IsEmpty(n.Chain.Type) {
		if !validator.IsNFTChainType(n.Chain.Type) {
			log.Errorf("Failed to add nft chain, Invalid type")
			return fmt.Errorf("invalid type: '%s'", n.Chain.Type)
		}
		ch.Type = nftables.ChainType(n.Chain.Type)
	}

	if !validator.IsEmpty(n.Chain.Priority) {
		v, err := validator.IsInt(n.Chain.Priority)
		if err != nil {
			log.Errorf("Failed to add nft chain, Invalid priority")
			return fmt.Errorf("invalid priority: '%s'", n.Chain.Priority)
		}
		ch.Priority = nftables.ChainPriorityRef(nftables.ChainPriority(v))
	}

	if !validator.IsEmpty(n.Chain.Policy) {
		if !validator.IsNFTChainPolicy(n.Chain.Policy) {
			log.Errorf("Failed to add nft chain, Invalid policy")
			return fmt.Errorf("invalid policy: '%s'", n.Chain.Policy)
		}
		ch.Policy = convertToUnixPolicy(n.Chain.Policy)
	}

	return nil
}

func (n *Nft) AddChain(w http.ResponseWriter) error {
	ch := nftables.Chain{}
	if err := n.ParseChain(&ch); err != nil {
		log.Errorf("Failed to parse chain: %v", err)
		return err
	}

	tableMap := make(map[string]*nftables.Table)
	if err := getTablesAndCreateMap(tableMap); err != nil {
		log.Errorf("Failed to acquire nft tables: %v", err)
		return fmt.Errorf("failed to acquire nft tables: %v", err)
	}

	key := createTableMapKey(n.Chain.Table, convertToUnixFamily(n.Chain.Family))
	tbl, ok := tableMap[key]
	if !ok {
		log.Errorf("Failed to add chain='%s', table_family not found='%s'", key)
		return fmt.Errorf("table family not found='%s'", key)
	}
	ch.Table = tbl

	c := newConnection()
	c.AddChain(&ch)

	if err := c.Flush(); err != nil {
		log.Errorf("Unable to flush connection: %v", err)
		return err
	}

	return web.JSONResponse("added", w)
}

func (n *Nft) RemoveChain(w http.ResponseWriter) error {
	ch := nftables.Chain{}
	if err := n.ParseChain(&ch); err != nil {
		log.Errorf("Failed to parse chain: %v", err)
		return err
	}

	chainMap := make(map[string]*nftables.Chain)
	if err := getChainsAndCreateMap(chainMap); err != nil {
		log.Errorf("Failed to acquire nft chains: %v", err)
		return fmt.Errorf("failed to acquire nft chains: %v", err)
	}

	key := createChainMapKey(n.Chain.Table, n.Chain.Name, convertToUnixFamily(n.Chain.Family))
	v, ok := chainMap[key]
	if !ok {
		log.Errorf("Failed to delete chain='%s', table_chain_family not found='%s'", key)
		return fmt.Errorf("table chain family not found='%s'", key)
	}
	ch.Table = v.Table

	c := newConnection()
	c.DelChain(&ch)

	if err := c.Flush(); err != nil {
		log.Errorf("Unable to flush connection: %v", err)
		return err
	}

	return web.JSONResponse("removed", w)
}

func (n *Nft) ShowChain(w http.ResponseWriter) error {
	chainMap := make(map[string]*nftables.Chain)
	if err := getChainsAndCreateMap(chainMap); err != nil {
		log.Errorf("Failed to acquire nft chains: %v", err)
		return fmt.Errorf("failed to acquire nft chains: %v", err)
	}

	if !validator.IsEmpty(n.Chain.Name) && !validator.IsEmpty(n.Chain.Table) && !validator.IsEmpty(n.Chain.Family) {
		key := createChainMapKey(n.Chain.Table, n.Chain.Name, convertToUnixFamily(n.Chain.Family))
		v, ok := chainMap[key]
		if !ok {
			return fmt.Errorf("chain not found='%s'", n.Chain.Name)
		}
		result := make(map[string]*nftables.Chain)
		result[n.Chain.Name] = v
		return web.JSONResponse(result, w)
	}

	return web.JSONResponse(chainMap, w)
}

func (n *Nft) SaveNFT(w http.ResponseWriter) error {
	stdout, err := system.ExecAndCapture("nft", "list", "ruleset")
	if err != nil {
		log.Errorf("Failed to acquire command output=%v", err)
		return fmt.Errorf("Failed to acquire command output=%v", err)
	}

	if err := ioutil.WriteFile(nftFilePath, []byte(stdout), 0644); err != nil {
		log.Errorf("Failed to save table info: %v", err)
		return err
	}

	return web.JSONResponse("saved", w)
}

func (n *Nft) RunNFT(w http.ResponseWriter) error {
	cmd := n.Command[0]
	n.Command = n.Command[1:]
	args := strings.Join(n.Command, " ")

	stdout, err := system.ExecAndCapture(cmd, args)
	if err != nil {
		log.Errorf("Failed to run command='%s %s', command output=%v", cmd, args, err)
		return fmt.Errorf("Failed to acquire command output=%v", err)
		//return fmt.Errorf("Failed to run command='%s %s', command output=%v", cmd, args, err)
	}

	return web.JSONResponse(stdout, w)
}
