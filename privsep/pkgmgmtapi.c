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
pkg_open_handle_s(
    PTDNF_CMD_ARGS pArgs,
    PTDNF *ppTdnf
    )
{
    uint32_t dwError = 0;
    int nLocked = 0;
    PTDNF pTdnf = NULL;

    if(!pArgs || !ppTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFOpenHandle(pArgs, &pTdnf);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_handle_list_add(pTdnf);
    BAIL_ON_PMD_ERROR(dwError);

    *ppTdnf = pTdnf;
cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;
error:
    if(ppTdnf)
    {
        *ppTdnf = 0;
    }
    if(pTdnf)
    {
        TDNFCloseHandle(pTdnf);
    }
    goto cleanup;
}

unsigned32
pkg_close_handle_s(
    PTDNF pTdnf
    )
{
    uint32_t dwError = 0;

    if(!pTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = privsep_handle_list_remove(pTdnf);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);

    TDNFCloseHandle(pTdnf);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);

cleanup:
    return dwError;

error:
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

unsigned32
pkg_count_s(
    PTDNF pTdnf,
    unsigned32* pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    int nLocked = 0;

    if(!pTdnf || !pdwCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFCountCommand(pTdnf, &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;

    *pdwCount = dwCount;
cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;
error:
    if(pdwCount)
    {
        *pdwCount = 0;
    }
    goto cleanup;
}


unsigned32
pkg_list_s(
    PTDNF pTdnf,
    unsigned32 nScope,
    char **ppszPackageNameSpecs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    int nLocked = 0;
    PTDNF_PKG_INFO pPkgInfo = NULL;

    if(!pTdnf || !ppszPackageNameSpecs || !ppPkgInfo || !pdwCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFInfo(
                  pTdnf,
                  nScope,
                  ppszPackageNameSpecs,
                  &pPkgInfo,
                  &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;

    *ppPkgInfo = pPkgInfo;
    *pdwCount = dwCount;
cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;
error:
    if(ppPkgInfo)
    {
        *ppPkgInfo = NULL;
    }
    if(pdwCount)
    {
        *pdwCount = 0;
    }
    if(pPkgInfo)
    {
        TDNFFreePackageInfoArray(pPkgInfo, dwCount);
    }
    goto cleanup;
}

unsigned32
pkg_repolist_s(
    PTDNF pTdnf,
    TDNF_REPOLISTFILTER nFilter,
    PTDNF_REPO_DATA *ppRepoData
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    int nLocked = 0;
    PTDNF_REPO_DATA pRepoData = NULL;

    if(!pTdnf || !ppRepoData)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFRepoList(
                  pTdnf,
                  nFilter,
                  &pRepoData);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;

    *ppRepoData = pRepoData;
cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;
error:
    if(ppRepoData)
    {
        *ppRepoData = NULL;
    }
    if(pRepoData)
    {
        TDNFFreeRepos(pRepoData);
    }
    goto cleanup;
}

unsigned32
pkg_info_s(
    PTDNF pTdnf,
    PTDNF_PKG_INFO *ppPkgInfo
    )
{
    uint32_t dwError = 0;
    printf("Info\n");

    return dwError;
}

unsigned32
pkg_updateinfo_s(
    PTDNF pTdnf,
    TDNF_AVAIL nAvail,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO_SUMMARY* ppUpdateInfoSummary
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    uint32_t dwCount = 0;
    int nLocked = 0;

    PTDNF_UPDATEINFO_SUMMARY pUpdateInfoSummary = NULL;

    if(!pTdnf || !ppUpdateInfoSummary)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFUpdateInfoSummary(
                  pTdnf,
                  nAvail,
                  ppszPackageNameSpecs,
                  &pUpdateInfoSummary);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;

    *ppUpdateInfoSummary = pUpdateInfoSummary;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;

error:
    if(ppUpdateInfoSummary)
    {
        *ppUpdateInfoSummary = NULL;
    }
    if(pUpdateInfoSummary)
    {
        TDNFFreeUpdateInfoSummary(pUpdateInfoSummary);
    }
    goto cleanup;
}

unsigned32
pkg_version_s(
    char** ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    const char *pszVersionTemp = NULL;
    
    if(!ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszVersionTemp = (char *)TDNFGetVersion();
    if(IsNullOrEmptyString(pszVersionTemp))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszVersionTemp, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszVersion);
    goto cleanup;
}

unsigned32
pkg_resolve_s(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedInfo
    )
{
    uint32_t dwError = 0;
    int nLocked = 0;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;

    if(!pTdnf || !ppSolvedInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFResolve(pTdnf, nAlterType, &pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;

    *ppSolvedInfo = pSolvedInfo;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;

error:
    goto cleanup;
}

unsigned32
pkg_alter_s(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;
    int nLocked = 0;

    if(!pTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFResolve(pTdnf, nAlterType, &pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pSolvedInfo->nNeedAction)
    {
        dwError = ERROR_PMD_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = TDNFAlterCommand(pTdnf, nAlterType, pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;
cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_get_error_string_s(
    uint32_t dwErrorCode,
    char **ppszError
    )
{
    uint32_t dwError = 0;
    char *pszError = NULL;

    if(dwErrorCode < ERROR_TDNF_BASE || !ppszError)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = TDNFGetErrorString(dwErrorCode, &pszError);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszError = pszError;

cleanup:
    return dwError;

error:
    if(ppszError)
    {
        *ppszError = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszError);
    goto cleanup;
}
