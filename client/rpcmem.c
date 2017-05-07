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

uint32_t
PMDRpcClientConvertPkgInfoList(
    PTDNF_RPC_PKGINFO_ARRAY pRpcPkgInfoArray,
    PTDNF_PKG_INFO *ppPkgInfo
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;

    PTDNF_RPC_PKGINFO pRpcPkgInfo = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;
    PTDNF_PKG_INFO pPkgInfoTemp = NULL;

    if(!pRpcPkgInfoArray || !ppPkgInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwCount = pRpcPkgInfoArray->dwCount;

    pRpcPkgInfo = pRpcPkgInfoArray->pPkgInfo;
    for(i = 0; i < dwCount; ++i)
    {
        dwError = PMDAllocateMemory(sizeof(TDNF_PKG_INFO),
                                    (void **)&pPkgInfoTemp);
        BAIL_ON_PMD_ERROR(dwError);

        pPkgInfoTemp->dwEpoch = pRpcPkgInfo[i].dwEpoch;
        pPkgInfoTemp->dwInstallSizeBytes = pRpcPkgInfo[i].dwSize;
        if(pRpcPkgInfo[i].pwszName)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszName,
                          &pPkgInfoTemp->pszName);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszVersion)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszVersion,
                          &pPkgInfoTemp->pszVersion);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszArch)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszArch,
                          &pPkgInfoTemp->pszArch);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszRepoName)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszRepoName,
                          &pPkgInfoTemp->pszRepoName);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszSummary)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszSummary,
                          &pPkgInfoTemp->pszSummary);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszDescription)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszDescription,
                          &pPkgInfoTemp->pszDescription);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszFormattedSize)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszFormattedSize,
                          &pPkgInfoTemp->pszFormattedSize);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszRelease)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszRelease,
                          &pPkgInfoTemp->pszRelease);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszLicense)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszLicense,
                          &pPkgInfoTemp->pszLicense);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszUrl)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszUrl,
                          &pPkgInfoTemp->pszURL);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(!pPkgInfo)
        {
            pPkgInfo = pPkgInfoTemp;
        }
        else
        {
            PTDNF_PKG_INFO pTemp = pPkgInfo;
            while(pTemp->pNext) pTemp = pTemp->pNext;
            pTemp->pNext = pPkgInfoTemp;
        }
        pPkgInfoTemp = NULL;
    }

    *ppPkgInfo = pPkgInfo;

cleanup:
    return dwError;

error:
    if(ppPkgInfo)
    {
        *ppPkgInfo = NULL;
    }
    pkg_free_package_info_list(pPkgInfo);
    pkg_free_package_info_list(pPkgInfoTemp);
    goto cleanup;
}

uint32_t
PMDRpcClientConvertPkgInfo(
    PTDNF_RPC_PKGINFO_ARRAY pRpcPkgInfoArray,
    PTDNF_PKG_INFO *ppPkgInfo
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;

    PTDNF_RPC_PKGINFO pRpcPkgInfo = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;

    if(!pRpcPkgInfoArray || !ppPkgInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwCount = pRpcPkgInfoArray->dwCount;
    dwError = PMDAllocateMemory(sizeof(TDNF_PKG_INFO) * dwCount,
                                (void **)&pPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcPkgInfo = pRpcPkgInfoArray->pPkgInfo;
    for(i = 0; i < dwCount; ++i)
    {
        pPkgInfo[i].dwEpoch = pRpcPkgInfo[i].dwEpoch;
        pPkgInfo[i].dwInstallSizeBytes = pRpcPkgInfo[i].dwSize;
        if(pRpcPkgInfo[i].pwszName)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszName,
                          &pPkgInfo[i].pszName);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszVersion)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszVersion,
                          &pPkgInfo[i].pszVersion);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszArch)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszArch,
                          &pPkgInfo[i].pszArch);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszRepoName)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszRepoName,
                          &pPkgInfo[i].pszRepoName);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszSummary)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszSummary,
                          &pPkgInfo[i].pszSummary);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszDescription)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszDescription,
                          &pPkgInfo[i].pszDescription);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszFormattedSize)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszFormattedSize,
                          &pPkgInfo[i].pszFormattedSize);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszRelease)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszRelease,
                          &pPkgInfo[i].pszRelease);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszLicense)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszLicense,
                          &pPkgInfo[i].pszLicense);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pRpcPkgInfo[i].pwszUrl)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcPkgInfo[i].pwszUrl,
                          &pPkgInfo[i].pszURL);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppPkgInfo = pPkgInfo;

cleanup:
    return dwError;

error:
    if(ppPkgInfo)
    {
        *ppPkgInfo = NULL;
    }
    pkg_free_package_info_array(pPkgInfo, dwCount);
    goto cleanup;
}

uint32_t
PMDRpcClientConvertSolvedPkgInfo(
    PTDNF_RPC_SOLVED_PKG_INFO pRpcSolvedInfo,
    PTDNF_SOLVED_PKG_INFO *ppSolvedInfo
    )
{
    uint32_t dwError = 0;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;

    if(!pRpcSolvedInfo || !ppSolvedInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(TDNF_SOLVED_PKG_INFO),
                                (void **)&pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pSolvedInfo->nNeedAction = pRpcSolvedInfo->nNeedAction;
    pSolvedInfo->nNeedDownload = pRpcSolvedInfo->nNeedDownload;
    pSolvedInfo->nAlterType = pRpcSolvedInfo->nAlterType;

    if(pRpcSolvedInfo->pPkgsToUpgrade &&
       pRpcSolvedInfo->pPkgsToUpgrade->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsToUpgrade,
                      &pSolvedInfo->pPkgsToUpgrade);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsNotAvailable &&
       pRpcSolvedInfo->pPkgsNotAvailable->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsNotAvailable,
                      &pSolvedInfo->pPkgsNotAvailable);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsExisting &&
       pRpcSolvedInfo->pPkgsExisting->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsExisting,
                      &pSolvedInfo->pPkgsExisting);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsToInstall &&
       pRpcSolvedInfo->pPkgsToInstall->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsToInstall,
                      &pSolvedInfo->pPkgsToInstall);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsToDowngrade &&
       pRpcSolvedInfo->pPkgsToDowngrade->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsToDowngrade,
                      &pSolvedInfo->pPkgsToDowngrade);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsUnNeeded &&
       pRpcSolvedInfo->pPkgsUnNeeded->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsUnNeeded,
                      &pSolvedInfo->pPkgsUnNeeded);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsToReinstall &&
       pRpcSolvedInfo->pPkgsToReinstall->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsToReinstall,
                      &pSolvedInfo->pPkgsToReinstall);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsObsoleted &&
       pRpcSolvedInfo->pPkgsObsoleted->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsObsoleted,
                      &pSolvedInfo->pPkgsObsoleted);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pRpcSolvedInfo->pPkgsToRemove &&
       pRpcSolvedInfo->pPkgsToRemove->dwCount > 0)
    {
        dwError = PMDRpcClientConvertPkgInfoList(
                      pRpcSolvedInfo->pPkgsToRemove,
                      &pSolvedInfo->pPkgsToRemove);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pRpcSolvedInfo->pPkgsNotResolved &&
       pRpcSolvedInfo->pPkgsNotResolved->dwCount)
    {
        uint32_t i = 0;
        uint32_t dwCount = pRpcSolvedInfo->pPkgsNotResolved->dwCount;

        dwError = PMDAllocateMemory(
                      sizeof(char *) * (dwCount + 1),
                      (void **)&pSolvedInfo->ppszPkgsNotResolved);
        BAIL_ON_PMD_ERROR(dwError);

        for(i = 0; i < dwCount; ++i)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcSolvedInfo->pPkgsNotResolved->ppwszStrings[i],
                          &pSolvedInfo->ppszPkgsNotResolved[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppSolvedInfo = pSolvedInfo;

cleanup:
    return dwError;

error:
    if(ppSolvedInfo)
    {
        *ppSolvedInfo = NULL;
    }
    pkg_free_solvedinfo(pSolvedInfo);
    goto cleanup;
}

uint32_t
PMDRpcFreeString(
    char** ppszString
)
{
    uint32_t dwError = ERROR_SUCCESS;

    rpc_string_free((PBYTE*)ppszString, &dwError);

    return dwError;
}

uint32_t
PMDRpcFreeBinding(
    handle_t* pBinding
)
{
    uint32_t dwError = ERROR_SUCCESS;

    rpc_binding_free(pBinding, &dwError);

    return dwError;
}

void
PMDRpcClientFreeMemory(
    void* pMemory
    )
{
    if (pMemory)
    {
        uint32_t rpcStatus = rpc_s_ok;
        rpc_sm_client_free(pMemory, &rpcStatus);
    }
}

void
PMDRpcClientFreeStringArrayA(
    char**  ppszStrArray,
    uint32_t  dwCount
    )
{
    uint32_t iStr = 0;

    for (; iStr < dwCount; iStr++)
    {
        PMDRpcClientFreeStringA(ppszStrArray[iStr]);
    }
    PMDRpcClientFreeMemory(ppszStrArray);
}

void
PMDRpcClientFreeStringArrayW(
    wstring_t* ppwszStrArray,
    uint32_t  dwCount
    )
{
    uint32_t iStr = 0;

    for (; iStr < dwCount; iStr++)
    {
        PMDRpcClientFreeStringW(ppwszStrArray[iStr]);
    }
    PMDRpcClientFreeMemory(ppwszStrArray);
}

void
PMDRpcClientFreeStringA(
    char* pszStr
    )
{
    if (pszStr)
    {
        PMDRpcClientFreeMemory(pszStr);
    }
}

void
PMDRpcClientFreeStringW(
    wstring_t pwszStr
    )
{
    if (pwszStr)
    {
        PMDRpcClientFreeMemory(pwszStr);
    }
}

void
PMDRpcClientFreeRepoDataArray(
    PTDNF_RPC_REPODATA_ARRAY pRepos
    )
{
    uint32_t dwIndex = 0;
    if(pRepos)
    {
        for(dwIndex = 0; dwIndex < pRepos->dwCount; ++dwIndex)
        {
            PMDRpcClientFreeStringW(pRepos->pRepoData[dwIndex].pwszId);
            PMDRpcClientFreeStringW(pRepos->pRepoData[dwIndex].pwszName);
        }
        PMDRpcClientFreeMemory(pRepos->pRepoData);
        PMDRpcClientFreeMemory(pRepos);
    }
}

void
PMDRpcClientFreePkgInfoArray(
    PTDNF_RPC_PKGINFO_ARRAY pPkgInfoArray
    )
{
    uint32_t dwIndex = 0;
    if(pPkgInfoArray)
    {
        for(dwIndex = 0; dwIndex < pPkgInfoArray->dwCount; ++dwIndex)
        {
            PTDNF_RPC_PKGINFO pInfo = &pPkgInfoArray->pPkgInfo[dwIndex];
            PMDRpcClientFreeStringW(pInfo->pwszName);
            PMDRpcClientFreeStringW(pInfo->pwszVersion);
            PMDRpcClientFreeStringW(pInfo->pwszArch);
            PMDRpcClientFreeStringW(pInfo->pwszSummary);
            PMDRpcClientFreeStringW(pInfo->pwszRepoName);
            PMDRpcClientFreeStringW(pInfo->pwszDescription);
            PMDRpcClientFreeStringW(pInfo->pwszFormattedSize);
            PMDRpcClientFreeStringW(pInfo->pwszRelease);
            PMDRpcClientFreeStringW(pInfo->pwszLicense);
            PMDRpcClientFreeStringW(pInfo->pwszUrl);
        }
        PMDRpcClientFreeMemory(pPkgInfoArray->pPkgInfo);
        PMDRpcClientFreeMemory(pPkgInfoArray);
    }
}
