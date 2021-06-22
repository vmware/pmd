/*
 * Copyright © 2016-2017 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */


#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <tdnf/tdnftypes.h>
#include "pmdtypes.h"

uint32_t
pkg_open_handle(
    PPMDHANDLE hHandle,
    PTDNF_CMD_ARGS pArgs,
    PPKGHANDLE *phPkgHandle
    );

uint32_t
pkg_close_handle(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle
    );

uint32_t
pkg_check_local(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    const char *pszFolder
    );

uint32_t
pkg_clean(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_CLEANTYPE nCleanType,
    PTDNF_CLEAN_INFO* ppCleanInfo
    );

uint32_t
pkg_provides(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    const char *pszSpec,
    PTDNF_PKG_INFO* ppPkgInfo
    );

uint32_t
pkg_search(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_PKG_INFO* ppPkgInfo,
    uint32_t* punCount
    );

uint32_t
pkg_list(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    TDNF_SCOPE nScope,
    char **ppszPkgNameSpecs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

uint32_t
pkg_count(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    uint32_t *pdwCount
    );

uint32_t
pkg_repolist(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    TDNF_REPOLISTFILTER nRepoListFilter,
    PTDNF_REPO_DATA *ppRepoData
    );

uint32_t
pkg_reposync(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    PTDNF_REPOSYNC_ARGS pRepoSyncArgs
    );

uint32_t
pkg_updateinfo(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO *ppUpdateInfo
    );

uint32_t
pkg_updateinfo_summary(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO_SUMMARY *ppSummary
    );

uint32_t
pkg_resolve(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedInfo
    );

uint32_t
pkg_alter(
    PPMDHANDLE hHandle,
    PPKGHANDLE phPkgHandle,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO pSolvedInfo
    );

uint32_t
pkg_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

uint32_t
pkg_get_error_string(
    PPMDHANDLE hHandle,
    uint32_t dwErrorCode,
    char** ppszError
    );

void
pkg_free_repos(
    PTDNF_REPO_DATA pRepos
    );

void
pkg_free_package_info(
    PTDNF_PKG_INFO pPkgInfo
    );

void
pkg_free_package_info_array(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwLength
    );

void
pkg_free_package_info_list(
    PTDNF_PKG_INFO pPkgInfo
    );

void
pkg_free_updateinfo_summary(
    PTDNF_UPDATEINFO_SUMMARY pSummary
    );

void
pkg_free_solvedinfo(
    PTDNF_SOLVED_PKG_INFO pSolvedInfo
    );

#ifdef __cplusplus
}
#endif
