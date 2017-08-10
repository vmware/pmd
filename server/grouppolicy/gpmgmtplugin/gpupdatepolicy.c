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
pmd_gpmgmt_execute_updatepolicy(
    const PPMD_POLICY_DATA pPolicy
    )
{
    uint32_t dwError = 0;
    uint32_t dwError1 = 0;
    PTDNF_CMD_ARGS pArgs = NULL;
    PTDNF pTdnf = NULL;
    const char *pszAltertype = NULL;
    char *pszPkgErrString = NULL;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;

    if (!pPolicy)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PTDNF_CMD_ARGS), (void **)&pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_gpmgmt_update_pkgmgmt_args(pPolicy, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    //dwError = pmd_gpmgmt_print_tdnf_args(pArgs);
    //BAIL_ON_PMD_ERROR(dwError);

    if (!pArgs->ppszCmds[0])
    {
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pszAltertype = pArgs->ppszCmds[0];

    dwError = pmd_gpmgmt_open_tdnf(pArgs, &pTdnf);
    BAIL_ON_PMD_ERROR(dwError);

    if (!strcmp(pszAltertype, "update") || !strcmp(pszAltertype, "upgrade"))
    {
        dwError = pmd_gpmgmt_invoke_tdnf_alter(pTdnf, ALTER_UPGRADE);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if (!strcmp(pszAltertype, "downgrade"))
    {
        dwError = pmd_gpmgmt_invoke_tdnf_alter(pTdnf, ALTER_DOWNGRADE);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = ERROR_PMD_GPMGMT_UNKNOWN_POLICY;
        BAIL_ON_PMD_ERROR(dwError);
    }


cleanup :
    PMD_SAFE_FREE_MEMORY(pszPkgErrString);
    TDNFFreeCmdArgs(pArgs);

    if (pTdnf)
    {
        pkg_close_handle_s(pTdnf);
    }
return dwError;

error :
    dwError = pmd_gpmgmt_update_handle_error(dwError, pPolicy);

    if(dwError)
    {
        fprintf(stderr, "Execute update policy failed error code is %d \n", 
                        dwError);
    }
    goto cleanup;
}

uint32_t
pmd_gpmgmt_update_pkgmgmt_args(
    const PPMD_POLICY_DATA pPolicy,
    PTDNF_CMD_ARGS *ppArgs)
{
    uint32_t dwError = 0;
    PTDNF_CMD_ARGS pArgs = NULL;
    const json_t *pJsonPkgArray = NULL;
    const json_t *value = NULL;
    size_t dwPkgCount = 0;
    int nIndex = 0;
    const char *pszPkg = NULL;
    const char *pszAltertype = NULL;
    json_t *pJsonAltertype = NULL;

    if (!pPolicy || !ppArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pJsonPkgArray = json_array();

    dwError = PMDAllocateMemory(sizeof(TDNF_CMD_ARGS), (void **)&pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    //TODO: Check if they are valid
    pArgs->nAllowErasing = 1;
    pArgs->nAssumeNo = 0;
    pArgs->nAssumeYes = 1;
    pArgs->nBest = 1;
    pArgs->nCacheOnly = 0;
    pArgs->nDebugSolver = 0;
    pArgs->nNoGPGCheck = 0;
    pArgs->nRefresh = 0;
    pArgs->nShowDuplicates = 1;
    pArgs->nShowHelp = 0;
    pArgs->nShowVersion = 0;
    pArgs->nVerbose = 1;
    pArgs->nIPv4 = 1;
    pArgs->nIPv6 = 0;

    dwError = PMDAllocateString("/", &pArgs->pszInstallRoot);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(PKG_CONFIG_FILE_NAME,
                                &pArgs->pszConfFile);
    BAIL_ON_PMD_ERROR(dwError);

    pArgs->pszReleaseVer = NULL;

    if (!pPolicy->pszPolicyData)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }

    //get the json data from the policy and allocate memory;
    pJsonPkgArray = json_object_get(pPolicy->pszPolicyData, "packages");
    dwPkgCount = json_array_size(pJsonPkgArray);

    if (!json_is_array(pJsonPkgArray))
    {
        fprintf(stderr, "The package files are not an Json array \n");
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pArgs->nCmdCount = dwPkgCount + 1; // One extra for the tdnf command and the rest for the packages

    if (pArgs->nCmdCount == 0)
    {
        fprintf(stderr, "No packages found in the policy data in the \"packages\" key \n");
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(char **) * pArgs->nCmdCount,
                                (void **)&pArgs->ppszCmds);
    BAIL_ON_PMD_ERROR(dwError);

    pJsonAltertype = json_object_get(pPolicy->pszPolicyData, "altertype");
    if (!pJsonAltertype)
    {
        fprintf(stderr, "No \"altertype\" key found in the JSON \n");
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszAltertype = json_string_value(pJsonAltertype);
    if (!pszAltertype)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!strcmp(pszAltertype, "update") || !strcmp(pszAltertype, "upgrade") ||
        !strcmp(pszAltertype, "downgrade"))
    {
        dwError = PMDAllocateString(
            pszAltertype,
            &pArgs->ppszCmds[0]);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        fprintf(stderr, " Unsupported altertype in the \"altertype\" key of the Json \n");
        dwError = ERROR_PMD_GPMGMT_UNKNOWN_POLICY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    json_array_foreach(pJsonPkgArray, nIndex, value)
    {
        pszPkg = json_string_value(value);
        if (!pszPkg)
        {
            fprintf(stderr, " Invalid packages in the \"packages\" key of the Json \n");
            dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = PMDAllocateString(
            pszPkg,
            &pArgs->ppszCmds[nIndex + 1]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppArgs = pArgs;

cleanup:
    return dwError;

error:
    fprintf(stderr, "Populating default args for tdnf failed  \n");
    if (ppArgs)
    {
        *ppArgs = NULL;
    }
    TDNFFreeCmdArgs(pArgs);
    goto cleanup;
}

// Fail only on PMD and Unknown errors, ignore tdnf errors and continue
uint32_t
pmd_gpmgmt_update_handle_error(
    uint32_t dwErrorCode,
    const PPMD_POLICY_DATA pPolicy)
{
    uint32_t dwError = 0;
    char *pszError = NULL;

    if (!pPolicy)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    //Handle tdnf error
    if (dwErrorCode == 0 || dwErrorCode == ERROR_TDNF_CLI_NOTHING_TO_DO)
    {
        fprintf(stdout, "Success !!\n");
    }
    else if (dwErrorCode >= ERROR_TDNF_CLI_BASE && dwErrorCode < ERROR_TDNF_BASE)
    {
        dwError = TDNFCliGetErrorString(dwErrorCode, &pszError);
        BAIL_ON_PMD_ERROR(dwError);
        fprintf(stdout, "Error(%d) : %s\n", dwErrorCode, pszError);
    }
    else if (dwErrorCode >= ERROR_TDNF_BASE && dwErrorCode < ERROR_PMD_BASE)
    {
        dwError = TDNFGetErrorString(dwErrorCode, &pszError);
        BAIL_ON_PMD_ERROR(dwError);
        fprintf(stdout, "Error(%d) : %s\n", dwErrorCode, pszError);
    }
    else if (dwErrorCode >= ERROR_PMD_BASE)
    {
        // Return back these errors for the caller to handle
        fprintf(stdout, "PMD Error(%d)\n", dwErrorCode);
        dwError = dwErrorCode;
    }
    else
    {
        // Return back these errors for the caller to handle
        fprintf(stdout, "Unknown Error(%d)\n", dwErrorCode);
        dwError = dwErrorCode;
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszError);
    return dwError;

error:
    fprintf(stderr,
            "Retrieving error string for %d failed with %d\n",
            dwErrorCode,
            dwError);
    goto cleanup;
}

uint32_t
pmd_gpmgmt_print_tdnf_args(
    const PTDNF_CMD_ARGS pArgs)
{
    uint32_t dwError = 0;

    if (!pArgs)
    {
        fprintf(stdout, "No TDNF args");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fprintf(stdout, " pArgs->nAllowErasing = %d \n", pArgs->nAllowErasing);
    fprintf(stdout, " pArgs->nAssumeNo  = %d \n", pArgs->nAssumeNo);
    fprintf(stdout, " pArgs->nAssumeYes = %d \n", pArgs->nAssumeYes);
    fprintf(stdout, " pArgs->nBest = %d \n", pArgs->nBest);
    fprintf(stdout, " pArgs->nCacheOnly = %d \n", pArgs->nCacheOnly);
    fprintf(stdout, " pArgs->nDebugSolver = %d \n", pArgs->nDebugSolver);
    fprintf(stdout, " pArgs->nNoGPGCheck  = %d \n", pArgs->nNoGPGCheck);
    fprintf(stdout, " pArgs->nRefresh  = %d \n", pArgs->nRefresh);
    fprintf(stdout, " pArgs->nRpmVerbosity = %d \n", pArgs->nRpmVerbosity);
    fprintf(stdout, " pArgs->nShowDuplicates = %d \n", pArgs->nShowDuplicates);
    fprintf(stdout, " pArgs->nShowHelp = %d \n", pArgs->nShowHelp);
    fprintf(stdout, " pArgs->nShowVersion = %d \n", pArgs->nShowVersion);
    fprintf(stdout, " pArgs->nVerbose= %d \n", pArgs->nVerbose);
    fprintf(stdout, " pArgs->nIPv4 = %d \n", pArgs->nIPv4);
    fprintf(stdout, " pArgs->nIPv6 = %d \n", pArgs->nIPv6);

    if (!IsNullOrEmptyString(pArgs->pszInstallRoot))
        fprintf(stdout, " Install root is = %s \n", pArgs->pszInstallRoot);
    else
        fprintf(stdout, " Install root is = NULL \n");

    if (!IsNullOrEmptyString(pArgs->pszReleaseVer))
        fprintf(stdout, " Release version is = %s \n", pArgs->pszReleaseVer);
    else
        fprintf(stdout, " Release version is = NULL \n");

    fprintf(stdout, " Args count is %d \n", pArgs->nCmdCount);

    for (int i = 0; i < pArgs->nCmdCount; i++)
    {
        fprintf(stdout, " Arg[%d] = %s \n", i, pArgs->ppszCmds[i]);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_gpmgmt_invoke_tdnf_alter(
    const PTDNF pTdnf,
    const TDNF_ALTERTYPE nAlterType)
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    char chChoice = 'n';
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;
    int nLocked = 0;

    if (!pTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFResolve(pTdnf, nAlterType, &pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    if (pSolvedInfo->ppszPkgsNotResolved)
    {
        dwError = PrintNotAvailable(pSolvedInfo->ppszPkgsNotResolved);
        BAIL_ON_PMD_ERROR(dwError);
    }

    //Available in later versions of tdnf
    /*
    if (pSolvedInfo->ppszPkgsNotInstalled)
    {
        dwError = PrintNotInstalled(pSolvedInfo->ppszPkgsNotInstalled);
        BAIL_ON_PMD_ERROR(dwError);
    }
     */
    if (!pSolvedInfo->nNeedAction)
    {
        dwError = ERROR_TDNF_CLI_NOTHING_TO_DO;
        //If there are unresolved, error with no match
        if (pSolvedInfo->ppszPkgsNotResolved &&
            *pSolvedInfo->ppszPkgsNotResolved)
        {
            dwError = ERROR_TDNF_NO_MATCH;
        }
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PrintSolvedInfo(pSolvedInfo);

    if (pSolvedInfo->nNeedAction)
    {
        if (pSolvedInfo->nNeedDownload)
        {
            fprintf(stdout, "\nDownloading\n");
        }

        dwError = TDNFAlterCommand(pTdnf, nAlterType, pSolvedInfo);
        BAIL_ON_PMD_ERROR(dwError);

        fprintf(stdout, "\nComplete!\n");
    }

    pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 0;

cleanup:
    if (nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;

error:
    //fprintf(stderr, "Invoking TDNF alter failed  ErrCode = %d\n",dwError);
    goto cleanup;
}

uint32_t
pmd_gpmgmt_open_tdnf(
    const PTDNF_CMD_ARGS pArgs,
    PTDNF *ppTdnf)
{
    uint32_t dwError = 0;
    int nLocked = 0;
    PTDNF pTdnf = NULL;

    if (!pArgs || !ppTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgMgmtApi);
    nLocked = 1;

    dwError = TDNFOpenHandle(pArgs, &pTdnf);
    BAIL_ON_PMD_ERROR(dwError);

    *ppTdnf = pTdnf;
cleanup:
    if (nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgMgmtApi);
        nLocked = 0;
    }
    return dwError;
error:
    fprintf(stderr, "Opening TDNF handle failed \n");
    if (ppTdnf)
    {
        *ppTdnf = 0;
    }
    if (pTdnf)
    {
        TDNFCloseHandle(pTdnf);
    }
    goto cleanup;
}