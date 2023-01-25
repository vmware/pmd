// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package share

type Set struct {
	data map[string]bool
}

func (s *Set) Add(value string) {
	s.data[value] = true
}

func (s *Set) Remove(value string) {
	delete(s.data, value)
}

func (s *Set) Contains(value string) (exists bool) {
	_, exists = s.data[value]
	return
}

func (s *Set) Length() int {
	return len(s.data)
}

func (s *Set) Values() (values []string) {
	for val := range s.data {
		values = append(values, val)
	}
	return
}

func NewSet() *Set {
	return &Set{make(map[string]bool)}
}
