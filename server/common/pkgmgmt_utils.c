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

void
pkg_free_cmd_args(
    PTDNF_CMD_ARGS pCmdArgs
    )
{
    int nIndex = 0;
    if(pCmdArgs)
    {
        for(nIndex = 0; nIndex < pCmdArgs->nCmdCount; ++nIndex)
        {
            PMD_SAFE_FREE_MEMORY(pCmdArgs->ppszCmds[nIndex]);
        }
        PMD_SAFE_FREE_MEMORY(pCmdArgs->ppszCmds);
    }
    PMD_SAFE_FREE_MEMORY(pCmdArgs);
}

uint32_t
pkg_rpc_get_cmd_args(
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    PTDNF_CMD_ARGS *ppArgs
    )
{
    uint32_t dwError = 0;
    int nIndex = 0;
    PTDNF_CMD_ARGS pArgs = NULL;

    if(!pRpcArgs || !ppArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                            sizeof(TDNF_CMD_ARGS),
                            (void**)&pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    pArgs->nAllowErasing  = pRpcArgs->nAllowErasing;
    pArgs->nAssumeNo      = pRpcArgs->nAssumeNo;
    pArgs->nAssumeYes     = pRpcArgs->nAssumeYes;
    pArgs->nBest          = pRpcArgs->nBest;
    pArgs->nCacheOnly     = pRpcArgs->nCacheOnly;
    pArgs->nDebugSolver   = pRpcArgs->nDebugSolver;
    pArgs->nNoGPGCheck    = pRpcArgs->nNoGPGCheck;
    pArgs->nRefresh       = pRpcArgs->nRefresh;
    pArgs->nRpmVerbosity  = pRpcArgs->nRpmVerbosity;
    pArgs->nShowDuplicates= pRpcArgs->nShowDuplicates;
    pArgs->nShowHelp      = pRpcArgs->nShowHelp;
    pArgs->nShowVersion   = pRpcArgs->nShowVersion;
    pArgs->nVerbose       = pRpcArgs->nVerbose;
    pArgs->nIPv4          = pRpcArgs->nIPv4;
    pArgs->nIPv6          = pRpcArgs->nIPv6;

    if(IsNullOrEmptyString(pRpcArgs->pwszInstallRoot))
    {
        dwError = PMDAllocateString(
                             "/",
                             &pArgs->pszInstallRoot);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = PMDAllocateStringAFromW(
                             pRpcArgs->pwszInstallRoot,
                             &pArgs->pszInstallRoot);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pRpcArgs->pwszConfFile))
    {
        dwError = PMDAllocateString(
                             PKG_CONFIG_FILE_NAME,//TODO: replace with tdnf api
                             &pArgs->pszConfFile);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = PMDAllocateStringAFromW(
                             pRpcArgs->pwszConfFile,
                             &pArgs->pszConfFile);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pRpcArgs->pwszReleaseVer))
    {
        dwError = PMDAllocateStringAFromW(
                      pRpcArgs->pwszReleaseVer,
                      &pArgs->pszReleaseVer);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pRpcArgs->pCmds)
    {
        pArgs->nCmdCount = pRpcArgs->pCmds->dwCount;
        if(pArgs->nCmdCount)
        {
            dwError = PMDAllocateMemory(
                          pArgs->nCmdCount * sizeof(char*),
                          (void**)&pArgs->ppszCmds
                          );
            BAIL_ON_PMD_ERROR(dwError);
        }

        for(nIndex = 0; nIndex < pArgs->nCmdCount; ++nIndex)
        {
            dwError = PMDAllocateStringAFromW(
                          pRpcArgs->pCmds->ppwszStrings[nIndex],
                          &pArgs->ppszCmds[nIndex]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
/*
    if(pRpcArgs->pSetOpt)
    {
        dwError = TDNFCloneSetOpts(pRpcArgs->pSetOpt,
                                   &pArgs->pSetOpt);
        BAIL_ON_PMD_ERROR(dwError);
    }
*/
    *ppArgs = pArgs;

cleanup:
    return dwError;

error:
    if(ppArgs)
    {
        *ppArgs = NULL;
    }
    pkg_free_cmd_args(pArgs);
    goto cleanup;
}

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

uint32_t
pkg_get_scope_from_string(
    const char *pszScope,
    TDNF_SCOPE *pnScope
    )
{
    uint32_t dwError = 0;
    TDNF_SCOPE nScope = SCOPE_NONE;

    if(IsNullOrEmptyString(pszScope) || !pnScope)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!strcasecmp(pszScope, "all"))
    {
        nScope = SCOPE_ALL;
    }
    else if(!strcasecmp(pszScope, "installed"))
    {
        nScope = SCOPE_INSTALLED;
    }
    else if(!strcasecmp(pszScope, "available"))
    {
        nScope = SCOPE_AVAILABLE;
    }
    else if(!strcasecmp(pszScope, "updates"))
    {
        nScope = SCOPE_UPGRADES;
    }
    else if(!strcasecmp(pszScope, "downgrades"))
    {
        nScope = SCOPE_DOWNGRADES;
    }
    else
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pnScope = nScope;
cleanup:
    return dwError;

error:
    if(pnScope)
    {
        *pnScope = SCOPE_NONE;
    }
    goto cleanup;
}
