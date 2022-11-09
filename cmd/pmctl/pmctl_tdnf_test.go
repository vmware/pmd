// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 VMware, Inc.

package main

import (
	"testing"

	"github.com/vmware/pmd/pkg/web"
	"github.com/vmware/pmd/plugins/tdnf"
)

func tdnfTestIsInstalled(t *testing.T, token map[string]string, pkg string) bool {
	options := tdnf.ListOptions{ScopeOptions: tdnf.ScopeOptions{Installed: true}}
	msg, err := acquireTdnfList(&options, pkg, "", token)
	if err != nil {
		t.Errorf("list failed: %v\n", err)
	}
	list := msg.Message
	found := false
	for _, i := range list {
		if i.Name == pkg {
			found = true
			break
		}
	}
	return found
}

func tdnfTestInstall(t *testing.T, token map[string]string, pkg string) {
	options := tdnf.Options{}
	_, err := acquireTdnfAlterCmd(&options, "install", pkg, "", token)
	if err != nil {
		t.Errorf("install failed: %v\n", err)
	}
	if !tdnfTestIsInstalled(t, token, pkg) {
		t.Errorf("pkg '%v' did not get installed\n", pkg)
	}
}

func tdnfTestRemove(t *testing.T, token map[string]string, pkg string) {
	options := tdnf.Options{}
	_, err := acquireTdnfAlterCmd(&options, "erase", pkg, "", token)
	if err != nil {
		t.Errorf("erase failed: %v\n", err)
	}
	if tdnfTestIsInstalled(t, token, pkg) {
		t.Errorf("pkg '%v' did not get removed\n", pkg)
	}
}

func tdnfTestSkipUnsupported(t *testing.T) {
	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfVersion(&options, "", token)
	if err != nil {
		t.Skipf("skipping because installed tdnf does not support json: %v\n", err)
	}
}

func TestTdnfInfo(t *testing.T) {
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfCheckUpdate(&options, "", "", token)
	if err != nil {
		t.Errorf("check-update failed: %v\n", err)
	}
}

func TestTdnfClean(t *testing.T) {
	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfSimpleCommand(&options, "clean", "", token)
	if err != nil {
		t.Errorf("clean failed: %v\n", err)
	}
}

func TestTdnfMakeCache(t *testing.T) {
	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfSimpleCommand(&options, "makecache", "", token)
	if err != nil {
		t.Errorf("makecache failed: %v\n", err)
	}
}

func TestTdnfRepoList(t *testing.T) {
	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}
	_, err := acquireTdnfRepoList(&options, "", token)
	if err != nil {
		t.Errorf("repolist failed: %v\n", err)
	}
}

func TestTdnfRepoQuery(t *testing.T) {
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

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
	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.UpdateInfoOptions{}
	_, err := acquireTdnfUpdateInfoSummary(&options, "", "", token)
	if err != nil {
		t.Errorf("updateinfo failed: %v\n", err)
	}
}

func TestTdnfUpdateInfoList(t *testing.T) {
	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.UpdateInfoOptions{ModeOptions: tdnf.ModeOptions{List: true}}
	_, err := acquireTdnfUpdateInfo(&options, "", "", token)
	if err != nil {
		t.Errorf("updateinfo failed: %v\n", err)
	}
}

func TestTdnfAlter(t *testing.T) {
	pkg := "nano" // a package that we probably won't need in the image

	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.Options{}

	_, err := acquireTdnfAlterCmd(&options, "install", pkg, "", token)
	if err != nil {
		t.Errorf("install failed: %v\n", err)
	}
	if !tdnfTestIsInstalled(t, token, pkg) {
		t.Errorf("pkg '%v' did not get installed\n", pkg)
	}

	_, err = acquireTdnfAlterCmd(&options, "erase", pkg, "", token)
	if err != nil {
		t.Errorf("remove failed: %v\n", err)
	}
	if tdnfTestIsInstalled(t, token, pkg) {
		t.Errorf("pkg '%v' did not get removed\n", pkg)
	}
}

func TestTdnfHistory(t *testing.T) {
	pkg := "nano" // a package that we probably won't need in the test env

	tdnfTestSkipUnsupported(t)

	token, _ := web.BuildAuthTokenFromEnv()
	options := tdnf.HistoryCmdOptions{}

	tdnfTestInstall(t, token, pkg)
	tdnfTestRemove(t, token, pkg)

	msg, err := acquireTdnfHistoryList(&options, "", token)
	if err != nil {
		t.Errorf("history list failed: %v\n", err)
	}

	// determine last transaction id, which is for the 'erase' cmd above
	list := msg.Message
	removeId := list[len(list)-1].Id
	undoOptions := tdnf.HistoryCmdOptions{HistoryOptions: tdnf.HistoryOptions{From: removeId}}

	// undo it (so pkg gets reinstalled)
	_, err = acquireTdnfHistoryAlterCmd(&undoOptions, "undo", "", token)
	if err != nil {
		t.Errorf("history undo failed: %v\n", err)
	}
	if !tdnfTestIsInstalled(t, token, pkg) {
		t.Errorf("pkg '%v' erase did not get undone\n", pkg)
	}

	// redo it (so pkg gets removed again)
	_, err = acquireTdnfHistoryAlterCmd(&undoOptions, "redo", "", token)
	if err != nil {
		t.Errorf("history redo failed: %v\n", err)
	}
	if tdnfTestIsInstalled(t, token, pkg) {
		t.Errorf("pkg '%v' erase did not get redone\n", pkg)
	}
}
