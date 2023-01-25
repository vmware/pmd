// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package share

import (
	"errors"
	"strings"

	"github.com/vmware/pmd/pkg/validator"
)

func StringContains(list []string, s string) bool {
	set := NewSet()
	for _, v := range list {
		set.Add(v)
	}
	return set.Contains(s)
}

func StringDeleteSlice(list []string, s string) ([]string, error) {
	set := make(map[string]int)

	for k, v := range list {
		set[v] = k
	}

	i, v := set[s]
	if v {
		list = append(list[:i], list[i+1:]...)
		return list, nil
	}

	return nil, errors.New("slice not found")
}

func StringDeleteAllSlice(a []string, b []string) ([]string, error) {
	var s []string
	var err error
	for _, v := range b {
		if validator.IsArrayEmpty(s) {
			s, err = StringDeleteSlice(a, v)
		} else {
			s, err = StringDeleteSlice(s, v)
		}
	}

	return s, err
}

func UniqueSlices(s []string, t []string) []string {
	set := NewSet()

	list := []string{}
	for _, e := range s {
		if e == "" {
			continue
		}
		if v := set.Contains(e); !v {
			set.Add(e)
			list = append(list, strings.TrimSpace(e))
		}
	}

	for _, e := range t {
		if e == "" {
			continue
		}
		if v := set.Contains(e); !v {
			set.Add(e)
			list = append(list, strings.TrimSpace(e))
		}
	}

	return list
}
