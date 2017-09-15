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
chk_dce_err(
    error_status_t ecode,
    char* where,
    char* why,
    unsigned int fatal
    );

uint32_t
get_client_rpc_binding(
    rpc_binding_handle_t* binding_handle,
    rpc_if_handle_t interface_spec,
    const char* hostname,
    const char* username,
    const char* domain,
    const char* password,
    const char* protocol,
    const char* endpoint,
    const char* spn
    );

//rpcmem.c
uint32_t
PMDRpcClientConvertPkgInfo(
    PTDNF_RPC_PKGINFO_ARRAY pRpcPkgInfo,
    PTDNF_PKG_INFO *ppPkgInfo
    );

uint32_t
PMDRpcClientConvertPkgInfoList(
    PTDNF_RPC_PKGINFO_ARRAY pRpcPkgInfoArray,
    PTDNF_PKG_INFO *ppPkgInfo
    );

uint32_t
PMDRpcClientConvertSolvedPkgInfo(
    PTDNF_RPC_SOLVED_PKG_INFO pRpcSolvedPkgInfo,
    PTDNF_SOLVED_PKG_INFO *ppSolvedPkgInfo
    );

uint32_t
PMDRpcFreeString(
    char** ppszString
);

uint32_t
PMDRpcFreeBinding(
    handle_t* pBinding
);

void
PMDRpcClientFreeMemory(
    void* pMemory
    );

void
PMDRpcClientFreeStringArrayA(
    char**  ppszStrArray,
    uint32_t  dwCount
    );

void
PMDRpcClientFreeStringArrayW(
    wstring_t* ppwszStrArray,
    uint32_t  dwCount
    );

void
PMDRpcClientFreeStringA(
    char* pszStr
    );

void
PMDRpcClientFreeStringW(
    wstring_t pwszStr
    );

void
PMDRpcClientFreePkgInfoArray(
    PTDNF_RPC_PKGINFO_ARRAY pPkgInfoArray
    );

void
PMDRpcClientFreeRepoDataArray(
    PTDNF_RPC_REPODATA_ARRAY pRepos
    );

void
pmd_free_wstring_array(
    PPMD_WSTRING_ARRAY pArray
    );

//misc.c
uint32_t
PMDIsDceRpcError(
    uint32_t dwErrorCode
    );

uint32_t
PMDGetDceRpcErrorString(
    uint32_t dwRpcError,
    char** ppszErrorMessage
    );
//rpcpkgmisc.c
uint32_t
pkg_get_rpc_cmd_args(
    PTDNF_CMD_ARGS pArgs,
    PTDNF_RPC_CMD_ARGS *ppRpcArgs
    );

void
free_pkg_rpc_cmd_args(
    PTDNF_RPC_CMD_ARGS pArgs
    );
//usermgmt_rpc_misc.c
void
usermgmt_free_rpc_users(
    PPMD_RPC_USER_ARRAY pRpcUsers
    );

uint32_t
usermgmt_convert_users(
    PPMD_RPC_USER_ARRAY pRpcUsers,
    PPMD_USER *ppUsers
    );

void
usermgmt_free_rpc_groups(
    PPMD_RPC_GROUP_ARRAY pRpcGroups
    );

uint32_t
usermgmt_convert_groups(
    PPMD_RPC_GROUP_ARRAY pRpcGroups,
    PPMD_GROUP *ppGroups
    );

int
privsepd_client_get_hashed_creds(
    int nPluginType,
    const char *pszUser,
    char **ppszSalt,
    unsigned char **pbytes_s,
    int *plen_s,
    unsigned char **pbytes_v,
    int *plen_v
    );
