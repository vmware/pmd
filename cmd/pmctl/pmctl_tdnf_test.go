// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"testing"

	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/tdnf"
)

func TdnfSkipUnsupported(t *testing.T) {
	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfVersion(&options, "", token)
	if err != nil {
		t.Skipf("skipping because installed tdnf does not support json: %v\n", err)
	}
}

func TestTdnfInfo(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.ListOptions{}
	msg, err := acquireTdnfInfoList(&options, "", "", token)
	if err != nil {
		t.Errorf("list failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in info\n")
	}
}

func TestTdnfList(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.ListOptions{}
	msg, err := acquireTdnfList(&options, "", "", token)
	if err != nil {
		t.Errorf("list failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in list\n")
	}
}

func TestTdnfListPkg(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.ListOptions{}
	msg, err := acquireTdnfList(&options, "tdnf", "", token)
	if err != nil {
		t.Errorf("list failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in list\n")
	}
}

func TestTdnfListPkgInstalled(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.ListOptions{ScopeOptions: tdnf.ScopeOptions{Installed: true}}
	msg, err := acquireTdnfList(&options, "tdnf", "", token)
	if err != nil {
		t.Errorf("list failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
		}
		if i.Repo != "@System" {
			t.Errorf("uninstalled package found in list: pkg=%s, repo=%s", i.Name, i.Repo)
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in list\n")
	}
}

func TestTdnfListPkgOneRepo(t *testing.T) {
	TdnfSkipUnsupported(t)

	repoId := "photon-release"

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.ListOptions{
		Options:      tdnf.Options{RepoId: repoId},
		ScopeOptions: tdnf.ScopeOptions{Available: true},
	}
	msg, err := acquireTdnfList(&options, "tdnf", "", token)
	if err != nil {
		t.Errorf("list failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
		}
		if i.Repo != repoId {
			t.Errorf("unexpected repo id found in list: pkg=%s, repo=%s", i.Name, i.Repo)
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in list\n")
	}
}

func TestTdnfCheckUpdate(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfCheckUpdate(&options, "", "", token)
	if err != nil {
		t.Errorf("check-update failed: %v\n", err)
	}
}

func TestTdnfClean(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfSimpleCommand(&options, "clean", "", token)
	if err != nil {
		t.Errorf("clean failed: %v\n", err)
	}
}

func TestTdnfMakeCache(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfSimpleCommand(&options, "makecache", "", token)
	if err != nil {
		t.Errorf("makecache failed: %v\n", err)
	}
}

func TestTdnfRepoList(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfRepoList(&options, "", token)
	if err != nil {
		t.Errorf("repolist failed: %v\n", err)
	}
}

func TestTdnfRepoQuery(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.RepoQueryOptions{}
	msg, err := acquireTdnfRepoQuery(&options, "tdnf", "", token)
	if err != nil {
		t.Errorf("repoquery failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in repoquery\n")
	}
}

func TestTdnfRepoQueryFile(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.RepoQueryOptions{QueryOptions: tdnf.QueryOptions{File: "/etc/tdnf/tdnf.conf"}}
	msg, err := acquireTdnfRepoQuery(&options, "", "", token)
	if err != nil {
		t.Errorf("repoquery failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in repoquery\n")
	}
}

func TestTdnfRepoQueryList(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.RepoQueryOptions{QueryOptions: tdnf.QueryOptions{List: true}}
	/* use t* to reduce size of output -
	   listing files of all packages takes a long time */
	msg, err := acquireTdnfRepoQuery(&options, "t*", "", token)
	if err != nil {
		t.Errorf("repoquery failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			for _, f := range i.Files {
				if f == "/etc/tdnf/tdnf.conf" {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in repoquery\n")
	}
}

func TestTdnfSearch(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	msg, err := acquireTdnfSearch(&options, "tdnf", "", token)
	if err != nil {
		t.Errorf("search failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == "tdnf" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("'tdnf' not found in search\n")
	}
}

func TestTdnfUpdateInfoSummary(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.UpdateInfoOptions{}
	_, err := acquireTdnfUpdateInfoSummary(&options, "", "", token)
	if err != nil {
		t.Errorf("updateinfo failed: %v\n", err)
	}
}

func TestTdnfUpdateInfoList(t *testing.T) {
	TdnfSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.UpdateInfoOptions{ModeOptions: tdnf.ModeOptions{List: true}}
	_, err := acquireTdnfUpdateInfo(&options, "", "", token)
	if err != nil {
		t.Errorf("updateinfo failed: %v\n", err)
	}
}
