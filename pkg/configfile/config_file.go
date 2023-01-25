// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 VMware, Inc.

package configfile

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"github.com/go-ini/ini"
)

type Meta struct {
	Path    string
	Cfg     *ini.File
	Section *ini.Section
}

func Load(path string) (*Meta, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{AllowNonUniqueSections: true, AllowShadows: true}, path)
	if err != nil {
		return nil, err
	}

	return &Meta{
		Path: path,
		Cfg:  cfg,
	}, nil
}

func (m *Meta) Save() error {
	return m.Cfg.SaveTo(m.Path)
}

func ParseKeyFromSectionString(path string, section string, key string) (string, error) {
	c, err := Load(path)
	if err != nil {
		return "", err
	}

	v := c.Cfg.Section(section).Key(key).String()
	if v == "" {
		return "", errors.New("not found")
	}

	return v, nil
}

func (m *Meta) SetKeySectionString(section string, key string, value string) error {
	s, err := m.Cfg.GetSection(section)
	if err != nil {
		s, err = m.Cfg.NewSection(section)
		if err != nil {
			return err
		}
	}

	s.Key(key).SetValue(value)
	return nil
}

func (m *Meta) SetKeySectionUint(section string, key string, value uint) error {
	s, err := m.Cfg.GetSection(section)
	if err != nil {
		s, err = m.Cfg.NewSection(section)
		if err != nil {
			return err
		}
	}

	v := strconv.FormatUint(uint64(value), 10)
	s.Key(key).SetValue(v)
	return nil
}

func (m *Meta) GetKeySectionString(section string, key string) string {
	return m.Cfg.Section(section).Key(key).String()
}

func (m *Meta) GetKeySectionUint(section string, key string) uint {
	v, _ := m.Cfg.Section(section).Key(key).Uint()
	return v
}

func (m *Meta) NewKeyToSectionString(section string, key string, value string) error {
	_, err := m.Cfg.SectionsByName(section)
	if err != nil {
		_, err = m.Cfg.NewSection(section)
		if err != nil {
			return err
		}
	}

	m.Cfg.Section(section).NewKey(key, value)
	return nil
}

func (m *Meta) NewSection(section string) error {
	s, err := m.Cfg.NewSection(section)
	if err != nil {
		return err
	}

	m.Section = s
	return nil
}

func (m *Meta) RemoveSection(section string, key string, value string) error {
	sections, err := m.Cfg.SectionsByName(section)
	if err != nil {
		return err
	}

	for i, s := range sections {
		if s.HasKey(key) && s.HasValue(value) {
			m.Cfg.DeleteSectionWithIndex(section, i)
			return nil
		} else {
			m.Cfg.DeleteSection(section)
			return nil
		}
	}

	if err := m.Save(); err != nil {
		return err
	}

	return errors.New("not found")
}

func (m *Meta) RemoveKeyFromSectionString(section string, key string, value string) error {
	sections, err := m.Cfg.SectionsByName(section)
	if err != nil {
		return err
	}

	for _, s := range sections {
		if s.HasKey(key) && s.HasValue(value) {
			s.DeleteKey(key)
			return nil
		}
	}

	if err := m.Save(); err != nil {
		return err
	}

	return errors.New("not found")
}

func (m *Meta) SetKeyToNewSectionString(key string, value string) {
	m.Section.NewKey(key, value)
}

func (m *Meta) SetKeyToNewSectionUint(key string, value uint) {
	s := strconv.FormatUint(uint64(value), 10)
	m.Section.NewKey(key, s)
}

func MapTo(cfg *ini.File, section string, v interface{}) error {
	if err := cfg.Section(section).MapTo(v); err != nil {
		return err
	}

	return nil
}

func RemoveFilesGlob(p string, pattern string, section string, key string, value string) error {
	matches, err := filepath.Glob(path.Join(p, pattern))
	if err != nil {
		return err
	}

	for _, f := range matches {
		m, err := Load(f)
		if err != nil {
			return err
		}

		sections, err := m.Cfg.SectionsByName(section)
		if err != nil {
			return err
		}

		for _, s := range sections {
			if s.HasKey(key) && s.HasValue(value) {
				os.Remove(m.Path)
				break
			}
		}

	}

	return nil
}

func RemoveFilesSectionGlob(p string, pattern string, section string, key string, value string) error {
	matches, err := filepath.Glob(path.Join(p, pattern))
	if err != nil {
		return err
	}

	for _, f := range matches {
		m, err := Load(f)
		if err != nil {
			return err
		}

		m.RemoveKeyFromSectionString(section, key, value)
		if err := m.Save(); err != nil {
			return err
		}
	}

	return nil
}
