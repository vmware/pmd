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
PMDRpcServerConvertPkgInfoList(
    PTDNF_PKG_INFO pPkgInfo,
    PTDNF_RPC_PKGINFO_ARRAY *ppRpcPkgInfo
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PTDNF_RPC_PKGINFO_ARRAY pRpcPkgInfo = NULL;
    PTDNF_RPC_PKGINFO pRpcPkgInfoTemp = NULL;
    PTDNF_PKG_INFO pPkgInfoTemp = NULL;

    if(!pPkgInfo || !ppRpcPkgInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwCount = 1;
    pPkgInfoTemp = pPkgInfo;
    while((pPkgInfoTemp = pPkgInfoTemp->pNext))++dwCount;

    dwError = PMDRpcServerAllocateMemory(
        sizeof(TDNF_RPC_PKGINFO_ARRAY),
        (void**)&pRpcPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcPkgInfo->dwCount = dwCount;
    dwError = PMDRpcServerAllocateMemory(sizeof(TDNF_RPC_PKGINFO) * dwCount,
                                         (void**)&pRpcPkgInfo->pPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcPkgInfoTemp = pRpcPkgInfo->pPkgInfo;
    for(pPkgInfoTemp = pPkgInfo;
        pPkgInfoTemp;
        pPkgInfoTemp = pPkgInfoTemp->pNext, ++pRpcPkgInfoTemp)
    {
        pRpcPkgInfoTemp->dwEpoch = pPkgInfoTemp->dwEpoch;
        pRpcPkgInfoTemp->dwSize = pPkgInfoTemp->dwInstallSizeBytes;

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszName,
                                             &pRpcPkgInfoTemp->pwszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszVersion,
                                             &pRpcPkgInfoTemp->pwszVersion);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszArch,
                                             &pRpcPkgInfoTemp->pwszArch);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszRepoName,
                                             &pRpcPkgInfoTemp->pwszRepoName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszSummary,
                                             &pRpcPkgInfoTemp->pwszSummary);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszDescription ?
                                             pPkgInfoTemp->pszDescription : "",
                                             &pRpcPkgInfoTemp->pwszDescription);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszFormattedSize,
                                             &pRpcPkgInfoTemp->pwszFormattedSize);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszRelease,
                                             &pRpcPkgInfoTemp->pwszRelease);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszLicense,
                                             &pRpcPkgInfoTemp->pwszLicense);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszURL,
                                             &pRpcPkgInfoTemp->pwszUrl);
        BAIL_ON_PMD_ERROR(dwError);
    }
    *ppRpcPkgInfo = pRpcPkgInfo;

cleanup:
    return dwError;

error:
    if(ppRpcPkgInfo)
    {
        *ppRpcPkgInfo = NULL;
    }
    PMDRpcServerFreePkgInfoArray(pRpcPkgInfo);
    goto cleanup;
}

uint32_t
PMDRpcServerConvertPkgInfoArray(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwCount,
    PTDNF_RPC_PKGINFO_ARRAY *ppRpcPkgInfo
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    PTDNF_RPC_PKGINFO_ARRAY pRpcPkgInfo = NULL;
    PTDNF_RPC_PKGINFO pRpcPkgInfoTemp = NULL;
    PTDNF_PKG_INFO pPkgInfoTemp = NULL;

    if(!pPkgInfo || !ppRpcPkgInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateMemory(
        sizeof(TDNF_RPC_PKGINFO_ARRAY),
        (void**)&pRpcPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcPkgInfo->dwCount = dwCount;

    dwError = PMDRpcServerAllocateMemory(sizeof(TDNF_RPC_PKGINFO) * dwCount,
                                         (void**)&pRpcPkgInfo->pPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pPkgInfoTemp = pPkgInfo;
    pRpcPkgInfoTemp = pRpcPkgInfo->pPkgInfo;
    for(dwIndex = 0;
        dwIndex < dwCount;
        ++dwIndex, ++pPkgInfoTemp, ++pRpcPkgInfoTemp)
    {
        pRpcPkgInfoTemp->dwEpoch = pPkgInfoTemp->dwEpoch;
        pRpcPkgInfoTemp->dwSize = pPkgInfoTemp->dwInstallSizeBytes;

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszName,
                                             &pRpcPkgInfoTemp->pwszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszVersion,
                                             &pRpcPkgInfoTemp->pwszVersion);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszArch,
                                             &pRpcPkgInfoTemp->pwszArch);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszRepoName,
                                             &pRpcPkgInfoTemp->pwszRepoName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszSummary,
                                             &pRpcPkgInfoTemp->pwszSummary);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszDescription ?
                                             pPkgInfoTemp->pszDescription : "",
                                             &pRpcPkgInfoTemp->pwszDescription);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszFormattedSize,
                                             &pRpcPkgInfoTemp->pwszFormattedSize);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszRelease,
                                             &pRpcPkgInfoTemp->pwszRelease);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszLicense,
                                             &pRpcPkgInfoTemp->pwszLicense);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateWFromA(pPkgInfoTemp->pszURL,
                                             &pRpcPkgInfoTemp->pwszUrl);
        BAIL_ON_PMD_ERROR(dwError);
    }
    pRpcPkgInfo->dwCount = dwCount;
    *ppRpcPkgInfo = pRpcPkgInfo;

cleanup:
    return dwError;

error:
    if(ppRpcPkgInfo)
    {
        *ppRpcPkgInfo = NULL;
    }
    PMDRpcServerFreePkgInfoArray(pRpcPkgInfo);
    goto cleanup;
}

void
PMDRpcServerFreeStringArray(
    PPMD_WSTRING_ARRAY pArray
    )
{
    uint32_t i = 0;
    if(!pArray)
    {
        return;
    }

    for (i = 0; i < pArray->dwCount; i++)
    {
        PMDRpcServerFreeMemory(pArray->ppwszStrings[i]);
    }
    PMDRpcServerFreeMemory(pArray->ppwszStrings);
    PMDRpcServerFreeMemory(pArray);
}

uint32_t
PMDRpcServerCopyStringArray(
    char **ppszStrings,
    PPMD_WSTRING_ARRAY *ppArray
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;
    char **ppszTempStrings = NULL;
    PPMD_WSTRING_ARRAY pArray = NULL;

    if(!ppszStrings || !ppArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    ppszTempStrings = ppszStrings;
    while(ppszTempStrings && *ppszTempStrings)
    {
        ++ppszTempStrings;
        ++dwCount;
    }

    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pArray);
    BAIL_ON_PMD_ERROR(dwError);

    pArray->dwCount = dwCount;

    if (dwCount > 0)
    {
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(wstring_t) * dwCount,
                      (void **)&pArray->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < dwCount; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          ppszStrings[i],
                          &pArray->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppArray = pArray;

cleanup:
    return dwError;

error:
    if(ppArray)
    {
        *ppArray = NULL;
    }

    PMDRpcServerFreeStringArray(pArray);
    goto cleanup;
}


void
PMDRpcServerFreeSolvedInfo(
    PTDNF_RPC_SOLVED_PKG_INFO pSolvedInfo
    )
{
    if(pSolvedInfo)
    {
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsNotAvailable);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsExisting);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsToInstall);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsToDowngrade);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsToUpgrade);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsToRemove);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsUnNeeded);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsToReinstall);
        PMDRpcServerFreePkgInfoArray(pSolvedInfo->pPkgsObsoleted);
        PMDRpcServerFreeStringArray(pSolvedInfo->pPkgsNotResolved);
        PMDRpcServerFreeMemory(pSolvedInfo);
    }
}

void
PMDRpcServerFreePkgInfoArray(
    PTDNF_RPC_PKGINFO_ARRAY pPkgInfoArray
    )
{
    if(pPkgInfoArray)
    {
        PMDRpcServerFreeMemory(pPkgInfoArray);
    }
}
