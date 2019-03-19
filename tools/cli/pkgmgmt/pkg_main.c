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
pkg_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PTDNF_CMD_ARGS pCmdArgs = NULL;
    TDNF_CLI_CMD_MAP arCmdMap[] =
    {
        {"check-update",       TDNFCliCheckUpdateCommand},
        {"clean",              TDNFCliCleanCommand},
        {"count",              TDNFCliCountCommand},
        {"distro-sync",        TDNFCliDistroSyncCommand},
        {"downgrade",          TDNFCliDowngradeCommand},
        {"erase",              TDNFCliEraseCommand},
        {"help",               TDNFCliHelpCommand},
        {"info",               TDNFCliInfoCommand},
        {"install",            TDNFCliInstallCommand},
        {"list",               TDNFCliListCommand},
        {"makecache",          TDNFCliMakeCacheCommand},
        {"provides",           TDNFCliProvidesCommand},
        {"whatprovides",       TDNFCliProvidesCommand},
        {"reinstall",          TDNFCliReinstallCommand},
        {"remove",             TDNFCliEraseCommand},
        {"repolist",           TDNFCliRepoListCommand},
        {"search",             TDNFCliSearchCommand},
        {"update",             TDNFCliUpgradeCommand},
        {"update-to",          TDNFCliUpgradeCommand},
        {"upgrade",            TDNFCliUpgradeCommand},
        {"upgrade-to",         TDNFCliUpgradeCommand},
        {"updateinfo",         TDNFCliUpdateInfoCommand},
        {"version",            pkg_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(TDNF_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    PMD_PKG_CLI_CONTEXT stCliContext = {0};
    TDNF_CLI_CONTEXT stContext = {0};

    stContext.pUserData = &stCliContext;

    stContext.pFnCount      = pkg_invoke_count;
    stContext.pFnAlter      = pkg_invoke_alter;
    stContext.pFnInfo       = pkg_invoke_info;
    stContext.pFnList       = pkg_invoke_list;
    stContext.pFnRepoList   = pkg_invoke_repolist;
    stContext.pFnResolve    = pkg_invoke_resolve;
    stContext.pFnUpdateInfo = pkg_invoke_updateinfo;
    stContext.pFnUpdateInfoSummary = pkg_invoke_updateinfo_summary;

    dwError = pkg_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        show_help();
    }
    else if(pCmdArgs->nCmdCount > 0)
    {
        pszCmd = pCmdArgs->ppszCmds[0];
        while(nCommandCount > 0)
        {
            --nCommandCount;
            if(!strcmp(pszCmd, arCmdMap[nCommandCount].pszCmdName))
            {

                nFound = 1;

                dwError = rpc_open(
                              "pkg",
                              pMainArgs->pszServer,
                              pMainArgs->pszUser,
                              pMainArgs->pszDomain,
                              pMainArgs->pszPass,
                              pMainArgs->pszSpn,
                              &stCliContext.hPMD);
                BAIL_ON_CLI_ERROR(dwError);

                stContext.hTdnf = stCliContext.hPMD;

                dwError = pkg_open_handle(stCliContext.hPMD,
                                          pCmdArgs,
                                          &stCliContext.hPkgHandle);
                BAIL_ON_CLI_ERROR(dwError);

                dwError = arCmdMap[nCommandCount].pFnCmd(&stContext, pCmdArgs);
                BAIL_ON_CLI_ERROR(dwError);
                break;
            }
        };
        if(!nFound)
        {
            dwError = ERROR_PMD_FAIL;
            show_no_such_cmd(pszCmd);
            BAIL_ON_CLI_ERROR(dwError);
        }
    }
    else
    {
        pkg_show_help();
    }

cleanup:
    if(stCliContext.hPMD && stCliContext.hPkgHandle)
    {
        pkg_close_handle(stCliContext.hPMD, stCliContext.hPkgHandle);
    }
    rpc_free_handle(stCliContext.hPMD);
    if(pCmdArgs)
    {
        pkg_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    pkg_print_error(stCliContext.hPMD, dwError);

    if (dwError == ERROR_TDNF_CLI_NOTHING_TO_DO)
    {
        // Nothing to do should not return an error code
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
pkg_invoke_alter(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO pSolvedPkgInfo
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_alter(pLocalContext->hPMD,
                     pLocalContext->hPkgHandle,
                     nAlterType,
                     pSolvedPkgInfo);
}

uint32_t
pkg_invoke_check_update(
    PTDNF_CLI_CONTEXT pContext,
    char** ppszPackageArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return 0;
}

uint32_t
pkg_invoke_count(
    PTDNF_CLI_CONTEXT pContext,
    uint32_t *pdwCount
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_count(pLocalContext->hPMD, pLocalContext->hPkgHandle, pdwCount);
}

uint32_t
pkg_invoke_info(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_LIST_ARGS pInfoArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_list(pLocalContext->hPMD,
                    pLocalContext->hPkgHandle,
                    pInfoArgs->nScope,
                    pInfoArgs->ppszPackageNameSpecs,
                    ppPkgInfo,
                    pdwCount);
}

uint32_t
pkg_invoke_list(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_LIST_ARGS pInfoArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_list(pLocalContext->hPMD,
                    pLocalContext->hPkgHandle,
                    pInfoArgs->nScope,
                    pInfoArgs->ppszPackageNameSpecs,
                    ppPkgInfo,
                    pdwCount);
}

uint32_t
pkg_invoke_repolist(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_REPOLISTFILTER nFilter,
    PTDNF_REPO_DATA *ppRepos
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_repolist(pLocalContext->hPMD,
                        pLocalContext->hPkgHandle,
                        nFilter, 
                        ppRepos);
}

uint32_t
pkg_invoke_resolve(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedPkgInfo
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_resolve(pLocalContext->hPMD,
                       pLocalContext->hPkgHandle,
                       nAlterType,
                       ppSolvedPkgInfo);
}

uint32_t
pkg_invoke_updateinfo(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_UPDATEINFO_ARGS pInfoArgs,
    PTDNF_UPDATEINFO *ppUpdateInfo
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;
    return pkg_updateinfo(
               pLocalContext->hPMD,
               pLocalContext->hPkgHandle,
               pInfoArgs->ppszPackageNameSpecs,
               ppUpdateInfo);
}

uint32_t
pkg_invoke_updateinfo_summary(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_AVAIL nAvail,
    PTDNF_UPDATEINFO_ARGS pInfoArgs,
    PTDNF_UPDATEINFO_SUMMARY *ppSummary
    )
{
    PPMD_PKG_CLI_CONTEXT pLocalContext = pContext->pUserData;

    return pkg_updateinfo_summary(
               pLocalContext->hPMD,
               pLocalContext->hPkgHandle,
               nAvail,
               pInfoArgs->ppszPackageNameSpecs,
               ppSummary);
}

uint32_t
pkg_show_version_cmd(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!pContext || !pContext->hTdnf || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = pkg_version(pContext->hTdnf, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "Version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}

uint32_t
pkg_print_error(
    PPMDHANDLE hPMD,
    uint32_t dwErrorCode
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;

    if(dwErrorCode >= ERROR_TDNF_CLI_BASE && dwErrorCode < ERROR_PKG_BASE_BEGIN)
    {
        dwError = TDNFCliGetErrorString(dwErrorCode, &pszError);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(hPMD && dwErrorCode >= ERROR_PKG_BASE_BEGIN && dwErrorCode <= ERROR_PKG_BASE_END)
    {
        dwError = pkg_get_error_string(hPMD, dwErrorCode, &pszError);
        BAIL_ON_CLI_ERROR(dwError);
    }
    if(dwErrorCode != ERROR_PMD_FAIL)
    {
        printf("Error(%d) : %s\n", dwErrorCode, pszError);
    }

cleanup:
    PMD_CLI_SAFE_FREE_MEMORY(pszError);
    return dwError;

error:
    printf(
        "Retrieving error string for %d failed with %d\n",
        dwErrorCode,
        dwError);
    goto cleanup;
}

uint32_t
get_error_string(
    uint32_t dwErrorCode,
    char** ppszError
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;
    int i = 0;
    int nCount = 0;
    
    PMD_ERROR_DESC arErrorDesc[] = PMD_CLI_ERROR_TABLE;

    nCount = sizeof(arErrorDesc)/sizeof(arErrorDesc[0]);

    for(i = 0; i < nCount; i++)
    {
        if (dwErrorCode == arErrorDesc[i].nCode)
        {
            dwError = PMDAllocateString(arErrorDesc[i].pszDesc, &pszError);
            BAIL_ON_CLI_ERROR(dwError);
            break;
        }
    }
    *ppszError = pszError;
cleanup:
    return dwError;
error:
    PMD_CLI_SAFE_FREE_MEMORY(pszError);
    goto cleanup;
}
