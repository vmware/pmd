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

//pkgmgmtapi.c
unsigned32
pkg_open_handle_s(
    PTDNF_CMD_ARGS pArgs,
    PTDNF *ppTdnf
    );

unsigned32
pkg_close_handle_s(
    PTDNF pTdnf
    );

uint32_t
pkg_get_scope_from_string(
    const char *pszScope,
    TDNF_SCOPE *pnScope
    );

unsigned32
pkg_search_s(
    PTDNF pTdnf,
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t* punCount
    );

unsigned32
pkg_count_s(
    PTDNF pTdnf,
    unsigned32* pdwCount
    );

unsigned32
pkg_list_s(
    PTDNF pTdnf,
    unsigned32 nScope,
    char **ppszPackageNameSpecs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

unsigned32
pkg_repolist_s(
    PTDNF pTdnf,
    TDNF_REPOLISTFILTER nFilter,
    PTDNF_REPO_DATA *ppRepoData
    );

unsigned32
pkg_info_s(
    PTDNF pTdnf,
    PTDNF_PKG_INFO *ppPkgInfo
    );

unsigned32
pkg_updateinfo_s(
    PTDNF pTdnf,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO_SUMMARY* ppUpdateInfoSummary
    );

unsigned32
pkg_version_s(
    char** ppszVersion
    );

unsigned32
pkg_resolve_s(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedInfo
    );

unsigned32
pkg_alter_s(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType
    );

unsigned32
pkg_get_error_string_s(
    uint32_t dwErrorCode,
    char **ppszError
    );
