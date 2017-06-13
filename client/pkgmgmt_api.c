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
rpc_open(
    const char* pszModule,
    const char* pszServer,
    const char* pszUser,
    const char* pszDomain,
    const char* pszPass,
    const char* pszSpn,
    PPMDHANDLE* phHandle
    )
{
    uint32_t dwError = 0;
    PMDHANDLE* hHandle = NULL;
    char* pszProt = PROTOCOL_TCP;
    char* pszEndpoint = PMD_RPC_TCP_END_POINT;
    int nIndex = 0;

    struct _stKnownIfspec
    {
        const char* pszModule;
        rpc_if_handle_t interface_spec;
    }knownIfspecs[] =
    {
#ifdef DEMO_ENABLED
        {"demo", demo_v1_0_c_ifspec},
#endif
        {"fwmgmt", fwmgmt_v1_0_c_ifspec},
        {"pkg", pkg_v1_0_c_ifspec},
        {"pmd", pmd_v1_0_c_ifspec},
        {"net", netmgmt_v1_0_c_ifspec},
        {"rolemgmt", rolemgmt_v1_0_c_ifspec},
        {"rpmostree", rpmostree_v1_0_c_ifspec},
        {"usermgmt", usermgmt_v1_0_c_ifspec},
    };

    int nNumKnownIfspecs =
        sizeof(knownIfspecs)/sizeof(knownIfspecs[0]);

    rpc_if_handle_t spec = NULL;
    for(nIndex = 0; nIndex < nNumKnownIfspecs; ++nIndex)
    {
        if(!strcasecmp(knownIfspecs[nIndex].pszModule, pszModule))
        {
            spec = knownIfspecs[nIndex].interface_spec;
            break;
        }
    }

    if(!spec)
    {
        fprintf(stderr, "Module %s is not registered\n", pszModule);
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pszServer || !strcasecmp(pszServer, "localhost"))
    {
        pszProt = PROTOCOL_NCALRPC;
        pszEndpoint = PMD_NCALRPC_END_POINT;
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMDHANDLE),
                  (void**)&hHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_client_rpc_binding(
              &hHandle->hRpc,
              spec,
              pszServer,
              pszUser,
              pszDomain,
              pszPass,
              pszProt,
              pszEndpoint,
              pszSpn);
    BAIL_ON_PMD_ERROR(dwError);

    *phHandle = hHandle;

cleanup:
    return dwError;
error:
    if(phHandle)
    {
        *phHandle = NULL;
    }
    PMDFreeMemory(hHandle);
    goto cleanup;
}

uint32_t
pkg_open_handle(
    PPMDHANDLE hHandle,
    PTDNF_CMD_ARGS pArgs,
    PPKGHANDLE *phPkgHandle
    )
{
    uint32_t dwError = 0;
    pkg_handle_t hPkgHandle = NULL;
    PTDNF_RPC_CMD_ARGS pRpcArgs = NULL;

    dwError = pkg_get_rpc_cmd_args(pArgs, &pRpcArgs);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(pkg_rpc_open_handle(
               hHandle->hRpc,
               pRpcArgs,
               &hPkgHandle), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    *phPkgHandle = hPkgHandle;

cleanup:
    free_pkg_rpc_cmd_args(pRpcArgs);
    return dwError;

error:
    if(phPkgHandle)
    {
        *phPkgHandle = NULL;
    }
    goto cleanup;
}

uint32_t
pkg_list(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_SCOPE nScope,
    char **ppszPkgNameSpecs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;

    PTDNF_RPC_PKGINFO_ARRAY pRpcInfo = NULL;

    PTDNF_PKG_INFO pPkgInfo = NULL;
    PPMD_WSTRING_ARRAY pPkgNameSpecs = NULL;
    char **ppszNameSpecsTemp = NULL;

    if(!ppPkgInfo || !ppszPkgNameSpecs || !pdwCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    ppszNameSpecsTemp = ppszPkgNameSpecs;

    dwError = PMDAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                               (void **)&pPkgNameSpecs);
    BAIL_ON_PMD_ERROR(dwError);

    while(*ppszNameSpecsTemp)
    {
        pPkgNameSpecs->dwCount++;
        ppszNameSpecsTemp++;
    }

    if(pPkgNameSpecs->dwCount > 0)
    {
        int i = 0;
        dwError = PMDAllocateMemory(sizeof(wstring_t) * pPkgNameSpecs->dwCount,
                                    (void **)&pPkgNameSpecs->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for(i = 0; i < pPkgNameSpecs->dwCount; ++i)
        {
            dwError = PMDAllocateStringWFromA(ppszPkgNameSpecs[i],
                                              &pPkgNameSpecs->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    DO_RPC(pkg_rpc_list(hHandle->hRpc,
                        hPkgHandle,
                        nScope,
                        pPkgNameSpecs,
                        &pRpcInfo), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcClientConvertPkgInfo(pRpcInfo, &pPkgInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppPkgInfo = pPkgInfo;
    *pdwCount = pRpcInfo->dwCount;

cleanup:
    if(pPkgNameSpecs)
    {
        pmd_free_wstring_array(pPkgNameSpecs);
    }
    if(pRpcInfo)
    {
        PMDRpcClientFreePkgInfoArray(pRpcInfo);
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
    goto cleanup;
}

uint32_t
pkg_count(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    uint32_t* pdwCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;

    DO_RPC(pkg_rpc_count(hHandle->hRpc, hPkgHandle, &dwCount), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwCount = dwCount;
cleanup:
    return dwError;
error:
    if(pdwCount)
    {
        *pdwCount = 0;
    }
    goto cleanup;
}

uint32_t
pkg_repolist(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_REPOLISTFILTER nRepoListFilter,
    PTDNF_REPO_DATA *ppRepoData
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    int i = 0;
    PTDNF_RPC_REPODATA_ARRAY pRpcRepoDataArray = NULL;
    PTDNF_RPC_REPODATA pRpcRepoData = NULL;

    PTDNF_REPO_DATA pRepoData = NULL;
    PTDNF_REPO_DATA pRepoTemp = NULL;

    if(!hHandle || !hPkgHandle || !ppRepoData)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_repolist(hHandle->hRpc,
                            hPkgHandle,
                            nRepoListFilter,
                            &pRpcRepoDataArray), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pRpcRepoDataArray || !pRpcRepoDataArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwCount = pRpcRepoDataArray->dwCount;
    pRpcRepoData = pRpcRepoDataArray->pRepoData;
    for(i = dwCount-1; i >= 0; --i)
    {
        dwError = PMDAllocateMemory(sizeof(TDNF_REPO_DATA),
                                    (void**)&pRepoTemp);
        BAIL_ON_PMD_ERROR(dwError);

        pRepoTemp->nEnabled = pRpcRepoData[i].nEnabled;
        dwError = PMDAllocateStringAFromW(pRpcRepoData[i].pwszId,
                                          &pRepoTemp->pszId);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(pRpcRepoData[i].pwszName,
                                          &pRepoTemp->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        pRepoTemp->pNext = pRepoData;
        pRepoData = pRepoTemp;
        pRepoTemp = NULL;
    }
    *ppRepoData = pRepoData;

cleanup:
    if(pRpcRepoDataArray)
    {
        PMDRpcClientFreeRepoDataArray(pRpcRepoDataArray);
    }
    return dwError;
error:
    if(ppRepoData)
    {
        *ppRepoData = NULL;
    }
    pkg_free_repos(pRepoTemp);
    pkg_free_repos(pRepoData);
    goto cleanup;
}

uint32_t
pkg_updateinfo(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO *ppUpdateInfo
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;

    PTDNF_UPDATEINFO pUpdateInfo = NULL;
    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY pRpcSummary = NULL;

    if(!hHandle || !ppUpdateInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_updateinfo_summary(hHandle->hRpc,
                                      hPkgHandle,
                                      &pRpcSummary), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pRpcSummary || !pRpcSummary->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(TDNF_UPDATEINFO) * pRpcSummary->dwCount,
                  (void**)&pUpdateInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppUpdateInfo = pUpdateInfo;

cleanup:
    return dwError;

error:
    if(ppUpdateInfo)
    {
        *ppUpdateInfo = NULL;
    }
    goto cleanup;
}

uint32_t
pkg_updateinfo_summary(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_AVAIL nAvail,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO_SUMMARY *ppSummary
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;

    PTDNF_UPDATEINFO_SUMMARY pSummary = NULL;
    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY pRpcSummary = NULL;

    if(!hHandle || !ppSummary)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_updateinfo_summary(hHandle->hRpc,
                                      hPkgHandle,
                                      &pRpcSummary), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pRpcSummary || !pRpcSummary->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(TDNF_UPDATEINFO_SUMMARY) * pRpcSummary->dwCount,
                  (void**)&pSummary);
    BAIL_ON_PMD_ERROR(dwError);

    for(dwIndex = 0; dwIndex < pRpcSummary->dwCount; ++dwIndex)
    {
        pSummary[dwIndex].nType =
            pRpcSummary->pRpcUpdateInfoSummaries[dwIndex].nType;
        pSummary[dwIndex].nCount =
            pRpcSummary->pRpcUpdateInfoSummaries[dwIndex].nCount;
    }

    *ppSummary = pSummary;

cleanup:
    return dwError;

error:
    if(ppSummary)
    {
        *ppSummary = NULL;
    }
    pkg_free_updateinfo_summary(pSummary);
    goto cleanup;
}

uint32_t
pkg_resolve(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedInfo
    )
{
    uint32_t dwError = 0;
    PTDNF_RPC_SOLVED_PKG_INFO pRpcSolvedInfo = NULL;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_resolve(hHandle->hRpc,
                           hPkgHandle,
                           nAlterType,
                           &pRpcSolvedInfo), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcClientConvertSolvedPkgInfo(pRpcSolvedInfo, &pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

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
pkg_alter(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO pSolvedPkgInfo
    )
{
    uint32_t dwError = 0;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_alter(hHandle->hRpc, hPkgHandle, nAlterType), dwError);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    wstring_t pwszVersion = NULL;
    char *pszVersion = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_version(hHandle->hRpc, &pwszVersion), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszVersion,
                  &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    PMDRpcClientFreeStringW(pwszVersion);
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszVersion);
    goto cleanup;
}

uint32_t
pmd_server_type(
    PPMDHANDLE hHandle,
    uint32_t* pdwServerType
    )
{
    uint32_t dwError = 0;
    uint32_t dwServerType = 0;

    if(!hHandle || !pdwServerType)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pmd_rpc_server_type(hHandle->hRpc, &dwServerType), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwServerType = dwServerType;
cleanup:
    return dwError;

error:
    if(pdwServerType)
    {
        *pdwServerType = 0;
    }
    goto cleanup;
}

uint32_t
rpmostree_server_info(
    PPMDHANDLE hHandle,
    PPMD_RPMOSTREE_SERVER_INFO_A* ppInfoA
    )
{
    uint32_t dwError = 0;
    PPMD_RPMOSTREE_SERVER_INFO pInfo = NULL;
    PPMD_RPMOSTREE_SERVER_INFO_A pInfoA = NULL;

    if(!hHandle || !ppInfoA)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(rpmostree_rpc_server_info(hHandle->hRpc, &pInfo), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pInfo)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMD_RPMOSTREE_SERVER_INFO_A),
                  (void**)&pInfoA);
    BAIL_ON_PMD_ERROR(dwError);

    pInfoA->dwServerType = pInfo->dwServerType;
    if(pInfo->pwszServerUrl)
    {
        dwError = PMDAllocateStringAFromW(
                      pInfo->pwszServerUrl,
                      &pInfoA->pszServerUrl);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pInfo->pwszCurrentHash)
    {
        dwError = PMDAllocateStringAFromW(
                      pInfo->pwszCurrentHash,
                      &pInfoA->pszCurrentHash);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppInfoA = pInfoA;

cleanup:
    return dwError;

error:
    if(ppInfoA)
    {
        *ppInfoA = pInfoA;
    }
    rpmostree_free_server_info(pInfoA);
    goto cleanup;
}

uint32_t
rpmostree_client_info(
    PPMDHANDLE hHandle,
    PPMD_RPMOSTREE_CLIENT_INFO_A* ppInfoA
    )
{
    uint32_t dwError = 0;
    PPMD_RPMOSTREE_CLIENT_INFO_A pInfoA = NULL;
    PPMD_RPMOSTREE_CLIENT_INFO pInfo = NULL;

    if(!hHandle || !ppInfoA)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(rpmostree_rpc_client_info(hHandle->hRpc, &pInfo), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pInfo)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMD_RPMOSTREE_CLIENT_INFO_A),
                  (void**)&pInfoA);
    BAIL_ON_PMD_ERROR(dwError);

    pInfoA->dwServerType = pInfo->dwServerType;
    if(pInfo->pwszComposeServer)
    {
        dwError = PMDAllocateStringAFromW(
                      pInfo->pwszComposeServer,
                      &pInfoA->pszComposeServer);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(pInfo->pwszCurrentHash)
    {
        dwError = PMDAllocateStringAFromW(
                      pInfo->pwszCurrentHash,
                      &pInfoA->pszCurrentHash);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppInfoA = pInfoA;

cleanup:
    rpmostree_free_client_info(pInfoA);
    return dwError;

error:
    if(ppInfoA)
    {
        *ppInfoA = NULL;
    }
    goto cleanup;
}

uint32_t
rpmostree_client_syncto(
    PPMDHANDLE hHandle,
    const char* pszHash
    )
{
    uint32_t dwError = 0;
    wstring_t pwszHash = NULL;

    if(!hHandle || !pszHash)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszHash, &pwszHash);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(rpmostree_rpc_client_syncto(hHandle->hRpc, pwszHash), dwError);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszHash);
    return dwError;

error:
    goto cleanup;
}

uint32_t
PMDFreeHandle(
    PPMDHANDLE hPMD
    )
{
    uint32_t dwError = 0;
    dwError = PMDRpcFreeBinding(&hPMD->hRpc);
    PMDFreeMemory(hPMD);
    return dwError;
}

void
pkg_free_repos(
    PTDNF_REPO_DATA pRepos
    )
{
    PTDNF_REPO_DATA pRepo = NULL;
    while(pRepos)
    {
        pRepo = pRepos;
        PMD_SAFE_FREE_MEMORY(pRepo->pszId);
        PMD_SAFE_FREE_MEMORY(pRepo->pszName);
        PMD_SAFE_FREE_MEMORY(pRepo->pszBaseUrl);
        PMD_SAFE_FREE_MEMORY(pRepo->pszMetaLink);
        PMD_SAFE_FREE_MEMORY(pRepo->pszUrlGPGKey);

        pRepos = pRepo->pNext;
        PMD_SAFE_FREE_MEMORY(pRepo);
    }
}

void
pkg_free_package_info(
    PTDNF_PKG_INFO pPkgInfo
    )
{
    if(!pPkgInfo)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszName);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszRepoName);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszVersion);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszArch);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszSummary);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszURL);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszLicense);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszDescription);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszFormattedSize);
    PMD_SAFE_FREE_MEMORY(pPkgInfo->pszRelease);
}

void
pkg_free_package_info_list(
    PTDNF_PKG_INFO pPkgInfo
    )
{
    PTDNF_PKG_INFO pTemp = NULL;
    if(!pPkgInfo)
    {
        return;
    }
    while(pPkgInfo)
    {
        pTemp = pPkgInfo->pNext;
        pkg_free_package_info(pPkgInfo);
        PMD_SAFE_FREE_MEMORY(pPkgInfo);
        pPkgInfo = pTemp;
    }
}

void
pkg_free_package_info_array(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwLength
    )
{
    uint32_t i = 0;
    if(pPkgInfo && dwLength > 0)
    {
        for(i = 0; i < dwLength; ++i)
        {
            pkg_free_package_info(&pPkgInfo[i]);
        }
    }
    PMD_SAFE_FREE_MEMORY(pPkgInfo);
}

uint32_t
pkg_get_error_string(
    PPMDHANDLE hHandle,
    uint32_t dwErrorCode,
    char** ppszError
    )
{
    uint32_t dwError = 0;
    wstring_t pwszError = NULL;
    char *pszError = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(pkg_rpc_get_error_string(hHandle->hRpc, dwErrorCode, &pwszError),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszError,
                  &pszError);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszError = pszError;

cleanup:
    PMDRpcClientFreeStringW(pwszError);
    return dwError;

error:
    if(ppszError)
    {
        *ppszError = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszError);
    goto cleanup;
}

void
pmd_free_wstring_array(
    PPMD_WSTRING_ARRAY pArray
    )
{
    if(!pArray)
    {
        return;
    }
    while(pArray->dwCount)
    {
        PMDFreeMemory(pArray->ppwszStrings[--pArray->dwCount]);
    }
    PMD_SAFE_FREE_MEMORY(pArray->ppwszStrings);
    PMDFreeMemory(pArray);
}

void
pkg_free_updateinfo_summary(
    PTDNF_UPDATEINFO_SUMMARY pSummary
    )
{
    if(pSummary)
    {
        PMD_SAFE_FREE_MEMORY(pSummary);
    }
}

void
pkg_free_solvedinfo(
    PTDNF_SOLVED_PKG_INFO pSolvedInfo
    )
{
    if(pSolvedInfo)
    {
        pkg_free_package_info_list(pSolvedInfo->pPkgsExisting);
        pkg_free_package_info_list(pSolvedInfo->pPkgsToInstall);
        pkg_free_package_info_list(pSolvedInfo->pPkgsToUpgrade);
        pkg_free_package_info_list(pSolvedInfo->pPkgsToDowngrade);
        pkg_free_package_info_list(pSolvedInfo->pPkgsNotAvailable);
        pkg_free_package_info_list(pSolvedInfo->pPkgsToRemove);
        pkg_free_package_info_list(pSolvedInfo->pPkgsToReinstall);
        PMDFreeStringArray(pSolvedInfo->ppszPkgsNotResolved);
        PMD_SAFE_FREE_MEMORY(pSolvedInfo);
    }
}

void
rpmostree_free_server_info(
    PPMD_RPMOSTREE_SERVER_INFO_A pInfoA
    )
{
    if(pInfoA)
    {
        PMD_SAFE_FREE_MEMORY(pInfoA->pszServerUrl);
        PMD_SAFE_FREE_MEMORY(pInfoA->pszCurrentHash);
        PMD_SAFE_FREE_MEMORY(pInfoA);
    }
}

void
rpmostree_free_client_info(
    PPMD_RPMOSTREE_CLIENT_INFO_A pInfoA
    )
{
    if(pInfoA)
    {
        PMD_SAFE_FREE_MEMORY(pInfoA->pszComposeServer);
        PMD_SAFE_FREE_MEMORY(pInfoA->pszCurrentHash);
        PMD_SAFE_FREE_MEMORY(pInfoA->pszLastSyncDate);
        PMD_SAFE_FREE_MEMORY(pInfoA);
    }
}
