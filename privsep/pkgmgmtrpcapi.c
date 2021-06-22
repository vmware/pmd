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
pkg_privsep_rpc_open_handle(
    handle_t hBinding,
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    pkg_privsep_handle_t *phPkgHandle
    )
{
    uint32_t dwError = 0;
    PTDNF_CMD_ARGS pArgs = NULL;
    PTDNF pTdnf = NULL;

    if(!hBinding || !pRpcArgs || !phPkgHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_rpc_get_cmd_args(pRpcArgs, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_handle_s(pArgs, &pTdnf);
    BAIL_ON_PMD_ERROR(dwError);

    *phPkgHandle = pTdnf;

cleanup:
    return dwError;

error:
    if(phPkgHandle)
    {
        *phPkgHandle = NULL;
    }
    if(pTdnf)
    {
        pkg_close_handle_s(pTdnf);
    }
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_close_handle(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle
    )
{
    uint32_t dwError = 0;
    PTDNF pTdnf = NULL;

    if(!hBinding || !hPkgHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_close_handle_s(hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_check_local(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    wstring_t pwszFolder
    )
{
    uint32_t dwError = 0;
    char *pszFolder = NULL;

    dwError = PMDAllocateStringAFromW(pwszFolder, &pszFolder);
    BAIL_ON_PMD_ERROR(dwError);

    if(!hBinding || !hPkgHandle || !pszFolder)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError =  pkg_check_local_s(hPkgHandle, pszFolder);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszFolder);
    return dwError;
error:

    goto cleanup;
}

unsigned32
pkg_privsep_rpc_provides(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    wstring_t pwszSpec,
    PTDNF_RPC_PKGINFO_ARRAY *ppInfo
    )
{
    uint32_t dwError = 0;
    char *pszSpec = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;
    PTDNF_RPC_PKGINFO_ARRAY pInfo = NULL;
    uint32_t dwCount = 0;

    dwError = PMDAllocateStringAFromW(pwszSpec, &pszSpec);
    BAIL_ON_PMD_ERROR(dwError);

    if(!hBinding || !hPkgHandle || !pszSpec)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError =  pkg_provides_s(hPkgHandle, pszSpec, &pPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);
    dwError = PMDRpcServerConvertPkgInfoList(pPkgInfo, &pInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppInfo = pInfo;
cleanup:
    PMD_SAFE_FREE_MEMORY(pszSpec);
    if(pPkgInfo)
    {
        TDNFFreePackageInfo(pPkgInfo);
    }
    return dwError;
error:
    if(pInfo)
    {
        PMDRpcServerFreeMemory(pInfo);
    }
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_clean(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    unsigned32 nCleanType,
    PTDNF_RPC_CLEAN_INFO* ppRpcCleanInfo
    )
{
    uint32_t dwError = 0;
    PTDNF_CLEAN_INFO pCleanInfo = NULL;
    PTDNF_RPC_CLEAN_INFO pRpcCleanInfo = NULL;

    if(!hBinding || !hPkgHandle || !ppRpcCleanInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError =  pkg_clean_s(hPkgHandle, nCleanType, &pCleanInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(TDNF_RPC_CLEAN_INFO),
                                         (void**)&pRpcCleanInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcCleanInfo->nCleanAll = pCleanInfo->nCleanAll;
    pRpcCleanInfo->nRpmDbFilesRemoved = pCleanInfo->nRpmDbFilesRemoved;
    pRpcCleanInfo->nMetadataFilesRemoved = pCleanInfo->nMetadataFilesRemoved;
    pRpcCleanInfo->nDbCacheFilesRemoved = pCleanInfo->nDbCacheFilesRemoved;
    pRpcCleanInfo->nPackageFilesRemoved = pCleanInfo->nPackageFilesRemoved;

    dwError = PMDRpcServerCopyStringArray(pCleanInfo->ppszReposUsed,
                                          &(pRpcCleanInfo->pszReposUsed));
    BAIL_ON_PMD_ERROR(dwError);

    *ppRpcCleanInfo = pRpcCleanInfo;

cleanup:
    if(pCleanInfo)
    {
        TDNFFreeCleanInfo(pCleanInfo);
    }
    return dwError;
error:
    if (ppRpcCleanInfo)
    {
        *ppRpcCleanInfo = NULL;
    }
    if (pRpcCleanInfo && pRpcCleanInfo->pszReposUsed)
    {
        int i = 0;
        for (i = 0; i < pRpcCleanInfo->pszReposUsed->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pRpcCleanInfo->pszReposUsed->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pRpcCleanInfo->pszReposUsed->ppwszStrings);
        PMDRpcServerFreeMemory(pRpcCleanInfo->pszReposUsed);
        PMDRpcServerFreeMemory(pRpcCleanInfo);
    }
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_search(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    PTDNF_RPC_PKGINFO_ARRAY *ppInfo,
    uint32_t* punCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;

    PTDNF_RPC_PKGINFO_ARRAY pInfo = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;

    PTDNF_CMD_ARGS pArgs = NULL;
    if(!hBinding || !hPkgHandle || !pRpcArgs || !ppInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_rpc_get_cmd_args(pRpcArgs, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError =  pkg_search_s(hPkgHandle, pArgs, &pPkgInfo, &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerConvertPkgInfoArray(pPkgInfo, dwCount, &pInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppInfo = pInfo;
    *punCount = dwCount;

cleanup:
    if(pPkgInfo)
    {
        TDNFFreePackageInfoArray(pPkgInfo, dwCount);
    }
    if (pArgs)
    {
        pkg_free_cmd_args(pArgs);
    }
    return dwError;
error:
    if(pInfo)
    {
        PMDRpcServerFreeMemory(pInfo);
    }
    goto cleanup;
}


unsigned32
pkg_privsep_rpc_count(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    unsigned32* pdwCount
    )
{
    uint32_t dwError = 0;

    if(!hBinding || !hPkgHandle || !pdwCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError =  pkg_count_s(hPkgHandle, pdwCount);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:

    goto cleanup;
}


unsigned32
pkg_privsep_rpc_list(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
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

    if(!hBinding || !hPkgHandle || !pPkgNameSpecs || !ppInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwCount = pPkgNameSpecs->dwCount;

    dwError = PMDAllocateMemory(sizeof(char *) * (dwCount + 1),
                                (void **)&ppszPackageNameSpecs);
    BAIL_ON_PMD_ERROR(dwError);

    for(dwCount = 0; dwCount < pPkgNameSpecs->dwCount; ++dwCount)
    {
        dwError = PMDAllocateStringAFromW(pPkgNameSpecs->ppwszStrings[dwCount],
                                          &ppszPackageNameSpecs[dwCount]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_list_s(
                  hPkgHandle,
                  nScope,
                  ppszPackageNameSpecs,
                  &pPkgInfo,
                  &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerConvertPkgInfoArray(pPkgInfo, dwCount, &pInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppInfo = pInfo;
cleanup:
    if(pPkgInfo)
    {
        TDNFFreePackageInfoArray(pPkgInfo, dwCount);
    }
    return dwError;
error:
    if(pInfo)
    {
        PMDRpcServerFreeMemory(pInfo);
    }
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_repolist(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    unsigned32 nFilter,
    PTDNF_RPC_REPODATA_ARRAY* ppRepoData
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    PTDNF_REPO_DATA pRepoData = NULL;
    PTDNF_REPO_DATA pRepoDataTemp = NULL;
    PTDNF_RPC_REPODATA_ARRAY pPMDRepoDataArray = NULL;
    PTDNF_RPC_REPODATA pRpcRepoData = NULL;
    wstring_t pwszTemp = NULL;

    if(!hBinding || !hPkgHandle || !ppRepoData)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_repolist_s(hPkgHandle, nFilter, &pRepoData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(
        sizeof(TDNF_RPC_REPODATA_ARRAY),
        (void**)&pPMDRepoDataArray);
    BAIL_ON_PMD_ERROR(dwError);

    for(dwCount = 0, pRepoDataTemp = pRepoData;
        pRepoDataTemp;
        pRepoDataTemp = pRepoDataTemp->pNext, ++dwCount);

    pPMDRepoDataArray->dwCount = dwCount;

    dwError = PMDRpcServerAllocateMemory(
        sizeof(TDNF_RPC_REPODATA)*dwCount,
        (void**)&pPMDRepoDataArray->pRepoData);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcRepoData = pPMDRepoDataArray->pRepoData;
    pRepoDataTemp = pRepoData;
    for(dwIndex = 0; dwIndex < dwCount; ++dwIndex)
    {
        dwError = PMDAllocateStringWFromA(pRepoDataTemp->pszId, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcRepoData->pwszId);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);
        dwError = PMDAllocateStringWFromA(pRepoDataTemp->pszName, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcRepoData->pwszName);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);

        pRpcRepoData->nEnabled = pRepoDataTemp->nEnabled;

        pRepoDataTemp = pRepoDataTemp->pNext;
        pRpcRepoData++;
    }

    *ppRepoData = pPMDRepoDataArray;
cleanup:
    if(pRepoData)
    {
        TDNFFreeRepos(pRepoData);
    }
    return dwError;
error:
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_reposync(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    PTDNF_RPC_REPOSYNC_ARGS pRpcRepoSyncArgs
    )
{
    uint32_t dwError = 0;
    PTDNF_REPOSYNC_ARGS pRepoSyncArgs = NULL;

    if(!hBinding || !hPkgHandle || !pRpcRepoSyncArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerConvertRepoSyncArgs(pRpcRepoSyncArgs, &pRepoSyncArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_reposync_s(hPkgHandle, pRepoSyncArgs);
    BAIL_ON_PMD_ERROR(dwError);

error:
    return dwError;
}

unsigned32
pkg_privsep_rpc_info(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
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
pkg_privsep_rpc_updateinfo_summary(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY* ppRpcUpdateInfoArray
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    uint32_t dwCount = 0;
    char* pszPackageNameSpecs = {NULL};
    PTDNF_UPDATEINFO_SUMMARY pUpdateInfoSummary = NULL;

    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY pRpcUpdateInfoArray = NULL;
    PTDNF_RPC_UPDATEINFO_SUMMARY pRpcUpdateInfoSummary = NULL;

    if(!hBinding || !hPkgHandle || !ppRpcUpdateInfoArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_updateinfo_s(
                  hPkgHandle,
                  &pszPackageNameSpecs,
                  &pUpdateInfoSummary);
    BAIL_ON_PMD_ERROR(dwError);

    dwCount = (UPDATE_ENHANCEMENT - UPDATE_UNKNOWN) + 1;

    dwError = PMDRpcServerAllocateMemory(
        sizeof(TDNF_RPC_UPDATEINFO_SUMMARY_ARRAY),
        (void**)&pRpcUpdateInfoArray);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcUpdateInfoArray->dwCount = dwCount;

    dwError = PMDRpcServerAllocateMemory(
        sizeof(TDNF_RPC_UPDATEINFO_SUMMARY) * dwCount,
        (void**)&pRpcUpdateInfoArray->pRpcUpdateInfoSummaries);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcUpdateInfoSummary = pRpcUpdateInfoArray->pRpcUpdateInfoSummaries;
    for(dwIndex = UPDATE_UNKNOWN;
        dwIndex <= UPDATE_ENHANCEMENT;
        ++dwIndex, ++pRpcUpdateInfoSummary)
    {
        pRpcUpdateInfoSummary->nCount = pUpdateInfoSummary[dwIndex].nCount;
        pRpcUpdateInfoSummary->nType = pUpdateInfoSummary[dwIndex].nType;
    }

    *ppRpcUpdateInfoArray = pRpcUpdateInfoArray;
cleanup:
    if(pUpdateInfoSummary)
    {
        TDNFFreeUpdateInfoSummary(pUpdateInfoSummary);
    }
    return dwError;
error:
    if(ppRpcUpdateInfoArray)
    {
        *ppRpcUpdateInfoArray = NULL;
    }
    goto cleanup;
}

unsigned32
pkg_privsep_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;
    wstring_t pwszVersion = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_version_s(&pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    if(IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
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
pkg_privsep_rpc_resolve(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    unsigned32 nAlterType,
    PTDNF_RPC_SOLVED_PKG_INFO *ppSolvedInfo
    )
{
    uint32_t dwError = 0;
    PTDNF_RPC_SOLVED_PKG_INFO pSolvedInfo = NULL;
    PTDNF_SOLVED_PKG_INFO pSolvedInfoA = NULL;

    if(!hBinding || !hPkgHandle || !ppSolvedInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_resolve_s(hPkgHandle, nAlterType, &pSolvedInfoA);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(TDNF_RPC_SOLVED_PKG_INFO),
                                         (void**)&pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pSolvedInfo->nNeedAction = pSolvedInfoA->nNeedAction;
    pSolvedInfo->nNeedDownload = pSolvedInfoA->nNeedDownload;
    pSolvedInfo->nAlterType = pSolvedInfoA->nAlterType;

    if(pSolvedInfoA->pPkgsNotAvailable)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsNotAvailable,
                      &pSolvedInfo->pPkgsNotAvailable);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsExisting)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsExisting,
                      &pSolvedInfo->pPkgsExisting);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsToInstall)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsToInstall,
                      &pSolvedInfo->pPkgsToInstall);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsToUpgrade)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsToUpgrade,
                      &pSolvedInfo->pPkgsToUpgrade);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsToDowngrade)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsToDowngrade,
                      &pSolvedInfo->pPkgsToDowngrade);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsToRemove)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsToRemove,
                      &pSolvedInfo->pPkgsToRemove);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsUnNeeded)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsUnNeeded,
                      &pSolvedInfo->pPkgsUnNeeded);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsToReinstall)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsToReinstall,
                      &pSolvedInfo->pPkgsToReinstall);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->pPkgsObsoleted)
    {
        dwError = PMDRpcServerConvertPkgInfoList(
                      pSolvedInfoA->pPkgsObsoleted,
                      &pSolvedInfo->pPkgsObsoleted);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pSolvedInfoA->ppszPkgsNotResolved)
    {
        dwError = PMDRpcServerCopyStringArray(
                      pSolvedInfoA->ppszPkgsNotResolved,
                      &pSolvedInfo->pPkgsNotResolved);
        BAIL_ON_PMD_ERROR(dwError);
    }

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
pkg_privsep_rpc_alter(
    handle_t hBinding,
    pkg_privsep_handle_t hPkgHandle,
    TDNF_ALTERTYPE nAlterType
    )
{
    uint32_t dwError = 0;

    if(!hBinding || !hPkgHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);


    dwError = pkg_alter_s(hPkgHandle, nAlterType);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

void
pkg_privsep_handle_t_rundown(void *handle)
{
    if (handle)
    {
        PTDNF pTdnf = (PTDNF)handle;

        pkg_close_handle_s(pTdnf);
    }
}

//helper functions
unsigned32
pkg_privsep_rpc_get_error_string(
    handle_t hBinding,
    unsigned32 dwErrorCode,
    wstring_t* ppwszError
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;
    wstring_t pwszError = NULL;

    if(!hBinding || !ppwszError)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_get_error_string_s(dwErrorCode, &pszError);
    BAIL_ON_PMD_ERROR(dwError);

    if(IsNullOrEmptyString(pszError))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszError, &pwszError);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszError = pwszError;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszError);
    return dwError;

error:
    if(ppwszError)
    {
        *ppwszError = NULL;
    }
    PMDRpcServerFreeMemory(pwszError);
    goto cleanup;
}
