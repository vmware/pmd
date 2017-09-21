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

#include "includes.h"

unsigned32
pkg_rpc_open_handle(
    handle_t hBinding,
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    pkg_handle_t *phPkgHandle
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PPKGHANDLE hPkgHandle = NULL;
    PTDNF_CMD_ARGS pArgs = NULL;

    if(!hBinding || !pRpcArgs || !phPkgHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = pkg_rpc_get_cmd_args(pRpcArgs, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rpc_open_privsep_internal(PKG_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_handle(hPMD, pArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = privsep_handle_list_add(hPMD, hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    *phPkgHandle = hPkgHandle;

cleanup:
    pkg_free_cmd_args(pArgs);
    return dwError;

error:
    if(phPkgHandle)
    {
        *phPkgHandle = NULL;
    }
    rpc_free_handle(hPMD);
    goto cleanup;
}

unsigned32
pkg_rpc_close_handle(
    handle_t hBinding,
    pkg_handle_t hPkgHandle
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !hPkgHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = privsep_handle_list_remove(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    rpc_free_handle(hPMD);

cleanup:
    return dwError;

error:
    goto cleanup;
}

unsigned32
pkg_rpc_count(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    unsigned32* pdwCount
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    uint32_t dwCount = 0;

    if(!hBinding || !hPkgHandle || !pdwCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = privsep_handle_list_get(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_count(hPMD, hPkgHandle, &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwCount = dwCount;
cleanup:
    return dwError;
error:

    goto cleanup;
}


unsigned32
pkg_rpc_list(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    unsigned32 nScope,
    PPMD_WSTRING_ARRAY pPkgNameSpecs,
    PTDNF_RPC_PKGINFO_ARRAY* ppInfo
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    PTDNF_RPC_PKGINFO_ARRAY pInfo = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;
    char **ppszPackageNameSpecs = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !hPkgHandle || !pPkgNameSpecs || !ppInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = privsep_handle_list_get(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_list_w(hPMD,
                       hPkgHandle,
                       nScope,
                       pPkgNameSpecs,
                       &pInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppInfo = pInfo;
cleanup:
    return dwError;
error:
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    if(pInfo)
    {
        PMDRpcServerFreeMemory(pInfo);
    }
    goto cleanup;
}

unsigned32
pkg_rpc_repolist(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    unsigned32 nFilter,
    PTDNF_RPC_REPODATA_ARRAY* ppRepoData
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    PTDNF_REPO_DATA pRepoData = NULL;
    PTDNF_REPO_DATA pRepoDataTemp = NULL;
    PTDNF_RPC_REPODATA_ARRAY pRpcRepoDataArray = NULL;
    PTDNF_RPC_REPODATA pRpcRepoData = NULL;
    wstring_t pwszTemp = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !hPkgHandle || !ppRepoData)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = privsep_handle_list_get(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_repolist_w(
                  hPMD,
                  hPkgHandle,
                  nFilter,
                  &pRpcRepoDataArray);
    BAIL_ON_PMD_ERROR(dwError);

    *ppRepoData = pRpcRepoDataArray;

cleanup:
    return dwError;

error:
    if(ppRepoData)
    {
        *ppRepoData = NULL;
    }
    goto cleanup;
}

unsigned32
pkg_rpc_info(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    unsigned32 nScope,
    PPMD_WSTRING_ARRAY pPkgNameSpecs,
    PTDNF_RPC_PKGINFO_ARRAY* ppInfo
    )
{
    uint32_t dwError = 0;
    printf("Info\n");

    return dwError;
}

unsigned32
pkg_rpc_updateinfo_summary(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY* ppRpcUpdateInfoArray
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY pRpcUpdateInfoArray = NULL;

    if(!hBinding || !hPkgHandle || !ppRpcUpdateInfoArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = privsep_handle_list_get(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_updateinfo_summary_w(
                  hPMD,
                  hPkgHandle,
                  AVAIL_AVAILABLE,
                  &pRpcUpdateInfoArray);
    BAIL_ON_PMD_ERROR(dwError);

    *ppRpcUpdateInfoArray = pRpcUpdateInfoArray;

cleanup:
    return dwError;

error:
    if(ppRpcUpdateInfoArray)
    {
        *ppRpcUpdateInfoArray = NULL;
    }
    goto cleanup;
}

unsigned32
pkg_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    wstring_t pwszVersion = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rpc_open_privsep_internal(PKG_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_version_w(hPMD, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMDRpcServerFreeMemory(pwszVersion);
    goto cleanup;
}

unsigned32
pkg_rpc_resolve(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    unsigned32 nAlterType,
    PTDNF_RPC_SOLVED_PKG_INFO *ppSolvedInfo
    )
{
    uint32_t dwError = 0;
    PTDNF_RPC_SOLVED_PKG_INFO pSolvedInfo = NULL;
    PTDNF_SOLVED_PKG_INFO pSolvedInfoA = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !hPkgHandle || !ppSolvedInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = privsep_handle_list_get(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_resolve_w(
                  hPMD,
                  hPkgHandle,
                  nAlterType,
                  &pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppSolvedInfo = pSolvedInfo;

cleanup:
    return dwError;

error:
    if(ppSolvedInfo)
    {
        *ppSolvedInfo = NULL;
    }
    PMDRpcServerFreeSolvedInfo(pSolvedInfo);
    goto cleanup;
}

unsigned32
pkg_rpc_alter(
    handle_t hBinding,
    pkg_handle_t hPkgHandle,
    TDNF_ALTERTYPE nAlterType
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !hPkgHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = privsep_handle_list_get(hPkgHandle, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_alter_w(
                  hPMD,
                  hPkgHandle,
                  nAlterType);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

void
pkg_handle_t_rundown(void *handle)
{
    PPMDHANDLE hPMD = NULL;
    if(privsep_handle_list_remove(handle, &hPMD) == 0)
    {
        if(hPMD)
        {
            rpc_free_handle(hPMD);
        }
    }
}
