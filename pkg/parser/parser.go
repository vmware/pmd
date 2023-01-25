// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package parser

import (
	"net"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

func ParseBool(str string) (bool, error) {
	b, err := strconv.ParseBool(str)
	if err == nil {
		return b, err
	}

	if strings.EqualFold(str, "yes") || strings.EqualFold(str, "y") || strings.EqualFold(str, "on") {
		return true, nil
	} else if strings.EqualFold(str, "no") || strings.EqualFold(str, "n") || strings.EqualFold(str, "off") {
		return false, nil
	}

	return false, errors.New("failed to parse")
}

func ParseIp(addr string) (net.IP, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		ips, err := net.LookupIP(addr)
		if err != nil {
			return nil, err
		}

		if ips[0].To4() != nil {
			return ips[0].To4(), nil
		} else if ips[0].To16() != nil {
			return ips[0].To16(), nil
		}
	}

	return ip, nil
}

func ParsePort(port string) (uint16, error) {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, errors.Wrap(err, "invalid port")
	}

	return uint16(p), nil
}

func ParseIpPort(s string) (string, string, error) {
	ip, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", err
	}

	if _, err := ParseIp(ip); err != nil {
		return "", "", err
	}

	if _, err := ParsePort(port); err != nil {
		return "", "", err
	}

	return ip, port, nil
}

func BuildIPFromBytes(ipBytes []uint8) string {
	s := make([]string, len(ipBytes))
	for v := range ipBytes {
		s[v] = strconv.Itoa(int(ipBytes[v]))
	}
	return strings.Join(s, ".")
}

func BuildIPv6FromBytes(ipBytes []uint8) string {
	s := make([]string, len(ipBytes))
	for v := range ipBytes {
		s[v] = strconv.Itoa(int(ipBytes[v]))
	}
	return strings.Join(s,"")
}

func BuildHexFromBytes(ipBytes []uint8) string {
	s := make([]string, len(ipBytes))
	for v := range ipBytes {
		s[v] = strconv.FormatInt(int64(ipBytes[v]), 16)
	}
	return strings.Join(s, "")
}

func BuildIpv6(s string) string {
	for i := 4; i < len(s); i += 3 {
		s = s[:i] + ":" + s[i:]
	}

	return s
}
