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

void
pkg_free_cmd_args(
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_rpc_get_cmd_args(
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    PTDNF_CMD_ARGS *ppArgs
    );

uint32_t
PMDRpcServerConvertPkgInfoArray(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwCount,
    PTDNF_RPC_PKGINFO_ARRAY *ppRpcPkgInfo
    );

uint32_t
PMDRpcServerConvertPkgInfoList(
    PTDNF_PKG_INFO pPkgInfo,
    PTDNF_RPC_PKGINFO_ARRAY *ppRpcPkgInfo
    );

uint32_t
PMDRpcServerCopyStringArray(
    char **ppszStrings,
    PPMD_WSTRING_ARRAY *ppArray
    );

void
PMDRpcServerFreeSolvedInfo(
    PTDNF_RPC_SOLVED_PKG_INFO pSolvedInfo
    );

void
PMDRpcServerFreePkgInfoArray(
    PTDNF_RPC_PKGINFO_ARRAY pPkgInfoArray
    );

uint32_t
pkg_get_scope_from_string(
    const char *pszScope,
    TDNF_SCOPE *pnScope
    );
