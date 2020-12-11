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

REST_MODULE _pkg_rest_module[] =
{
    {
        "/v1/pkg/version",
        {pkg_rest_get_version, NULL, NULL, NULL}
    },
    {
        "/v1/pkg/count",
        {pkg_rest_get_count, NULL, NULL, NULL}
    },
    {
        "/v1/pkg/repos",
        {pkg_rest_get_repolist, NULL, NULL, NULL}
    },
    {
        "/v1/pkg/list",
        {pkg_rest_list, NULL, NULL, NULL}
    },
    {
        "/v1/pkg/install",
        {NULL, NULL, pkg_rest_install, NULL}
    },
    {
        "/v1/pkg/update",
        {NULL, NULL, pkg_rest_update, NULL}
    },
    {
        "/v1/pkg/erase",
        {NULL, NULL, pkg_rest_erase, NULL}
    },
    {
        "/v1/pkg/distro_sync",
        {NULL, NULL, pkg_rest_distro_sync, NULL}
    },
    {
        "/v1/pkg/downgrade",
        {NULL, NULL, pkg_rest_downgrade, NULL}
    },
    {
        "/v1/pkg/reinstall",
        {NULL, NULL, pkg_rest_reinstall, NULL}
    },
    {0}
};

uint32_t
get_repodata_json_string(
    PTDNF_REPO_DATA pRepoData,
    char **ppszJson
    );

uint32_t
get_pkginfo_json_string(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwCount,
    char **ppszJson
    );

uint32_t
pkg_json_get_alter_args(
    const char *pszAlterCmd,
    const char **pszPackages,
    int nPkgCount,
    PTDNF_CMD_ARGS *ppArgs
    );

uint32_t
pkg_json_get_array(
    const char *pszInputJson,
    const char *pszName,
    char ***pppszStrings,
    int *pnCount
    );

uint32_t
pkg_get_cmd_string(
    TDNF_ALTERTYPE nAlterType,
    char ** ppszAlterCmd
    );

uint32_t
pkg_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _pkg_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_rest_get_cmd_args(
    const char **ppszCmds,
    int nCmdCount,
    PTDNF_CMD_ARGS *ppArgs
    )
{
    uint32_t dwError = 0;
    int nIndex = 0;
    PTDNF_CMD_ARGS pArgs = NULL;

    if(!ppszCmds ||  nCmdCount <= 0 || !ppArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(TDNF_CMD_ARGS), (void**)&pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    pArgs->nAllowErasing  = 0;
    pArgs->nAssumeNo      = 0;
    pArgs->nAssumeYes     = 0;
    pArgs->nBest          = 0;
    pArgs->nCacheOnly     = 0;
    pArgs->nDebugSolver   = 0;
    pArgs->nNoGPGCheck    = 0;
    pArgs->nRefresh       = 0;
    pArgs->nRpmVerbosity  = 0;
    pArgs->nShowDuplicates= 0;
    pArgs->nShowHelp      = 0;
    pArgs->nShowVersion   = 0;
    pArgs->nVerbose       = 0;
    pArgs->nIPv4          = 0;
    pArgs->nIPv6          = 0;

    dwError = PMDAllocateString("/", &pArgs->pszInstallRoot);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(PKG_CONFIG_FILE_NAME,
                                &pArgs->pszConfFile);
    BAIL_ON_PMD_ERROR(dwError);

    pArgs->nCmdCount = nCmdCount;

    dwError = PMDAllocateMemory(sizeof(char **) * nCmdCount,
                               (void **)&pArgs->ppszCmds);
    BAIL_ON_PMD_ERROR(dwError);

    for(nIndex = 0; nIndex < nCmdCount; ++nIndex)
    {
        dwError = PMDAllocateString(ppszCmds[nIndex],
                                    &pArgs->ppszCmds[nIndex]);
        BAIL_ON_PMD_ERROR(dwError);
    }

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
pkg_open_privsep_rest(
    PREST_AUTH pRestAuth,
    PPMDHANDLE *phPMD
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    char *pszUser = NULL;
    char *pszPass = NULL;

    if(!pRestAuth || !phPMD)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pRestAuth->nAuthMethod != REST_AUTH_BASIC)
    {
        dwError = ERROR_INVALID_REST_AUTH;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = base64_get_user_pass(
                  pRestAuth->pszAuthBase64,
                  &pszUser,
                  &pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rpc_open_privsep(
                  PKG_PRIVSEP,
                  pszUser,
                  pszPass,
                  NULL,
                  &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    *phPMD = hPMD;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    return dwError;

error:
    rpc_free_handle(hPMD);
    goto cleanup;
}

uint32_t
pkg_rest_get_version(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    char *pszOutputJson = NULL;
    PKEYVALUE pKeyValue = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = pkg_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("version", NULL, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_version(hPMD, &pKeyValue->pszValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
pkg_rest_get_count(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    char *pszOutputJson = NULL;
    PKEYVALUE pKeyValue = NULL;
    PTDNF_CMD_ARGS pArgs = NULL;
    const char *ppszCmds[] = {"count"};
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pRestArgs = (PREST_FN_ARGS)pInput;
    PPKGHANDLE hPkgHandle = NULL;

    if(!pRestArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_open_privsep_rest(pRestArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_rest_get_cmd_args(ppszCmds, 1, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_handle(hPMD, pArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_count(hPMD, hPkgHandle, &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("count", NULL, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pKeyValue->pszValue, "%d", dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    pkg_free_cmd_args(pArgs);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
pkg_rest_get_repolist(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    char *pszOutputJson = NULL;
    PTDNF_CMD_ARGS pArgs = NULL;
    PTDNF_REPO_DATA pRepoData = NULL;
    const char *ppszCmds[] = {"repolist"};
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pRestArgs = (PREST_FN_ARGS)pInput;
    PPKGHANDLE hPkgHandle = NULL;

    if(!pRestArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_open_privsep_rest(pRestArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_rest_get_cmd_args(ppszCmds, 1, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_handle(hPMD, pArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_repolist(hPMD, hPkgHandle, REPOLISTFILTER_ALL, &pRepoData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_repodata_json_string(pRepoData, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    pkg_free_cmd_args(pArgs);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
pkg_rest_list(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PTDNF_CMD_ARGS pArgs = NULL;
    PTDNF_PKG_INFO pPkgInfo = NULL;
    TDNF_SCOPE nScope = SCOPE_ALL;
    json_t *pJson = NULL;
    char *pszScope = NULL;
    char *pszPkgNameSpecs[] = {NULL};
    char *pszOutputJson = NULL;
    const char *ppszCmds[] = {"list"};
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pRestArgs = (PREST_FN_ARGS)pInput;
    const char *pszInputJson = NULL;
    PPKGHANDLE hPkgHandle = NULL;

    if(!pRestArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pRestArgs->pszInputJson;

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "filter", &pszScope);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = pkg_get_scope_from_string(pszScope, &nScope);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_open_privsep_rest(pRestArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_rest_get_cmd_args(ppszCmds, 1, &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_handle(hPMD, pArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_list(hPMD,
                       hPkgHandle,
                       nScope,
                       pszPkgNameSpecs,
                       &pPkgInfo,
                       &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_pkginfo_json_string(pPkgInfo, dwCount, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    pkg_free_package_info_array(pPkgInfo, dwCount);
    pkg_free_cmd_args(pArgs);
    PMD_SAFE_FREE_MEMORY(pszScope);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}


uint32_t
make_processed_pkgs_result(
    const char *pszAlterCmd,
    char **ppszPackages,
    int nPkgCount,
    char **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    json_t *pRoot = NULL;
    json_t *pRequestArray = NULL;
    char *pszOutputJson = NULL;
    char *pszOutputKey = NULL;
    int i = 0;

    if(IsNullOrEmptyString(pszAlterCmd) ||
       !ppszPackages ||
       !nPkgCount ||
       !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_object();
    if(!pRoot)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRequestArray = json_array();
    if(!pRequestArray)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < nPkgCount; ++i)
    {
        json_array_append_new(pRequestArray, json_string(ppszPackages[i]));
    }

    dwError = PMDAllocateStringPrintf(&pszOutputKey, "%srequest", pszAlterCmd);
    BAIL_ON_PMD_ERROR(dwError);

    json_object_set_new(pRoot, pszOutputKey, pRequestArray);

    pszOutputJson = json_dumps(pRoot, 0);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszOutputKey);
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    goto cleanup;
}

uint32_t
pkg_rest_alter(
    TDNF_ALTERTYPE nAlterType,
    PREST_FN_ARGS pRestArgs,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszAlterCmd = NULL;
    char **ppszPackages = NULL;
    PTDNF_CMD_ARGS pArgs = NULL;
    int nPkgCount = 0;
    int i = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PPKGHANDLE hPkgHandle = NULL;
    int nNothingToDo = 0;

    if(!pRestArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pRestArgs->pszInputJson;

    if(IsNullOrEmptyString(pszInputJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_json_get_array(pszInputJson,
                                 "packages",
                                 &ppszPackages,
                                 &nPkgCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_get_cmd_string(nAlterType, &pszAlterCmd);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_json_get_alter_args(pszAlterCmd,
                                      (const char **)ppszPackages,
                                      nPkgCount,
                                      &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_privsep_rest(pRestArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_open_handle(hPMD, pArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    //server will call resolve and alter - hence null for solvedinfo
    dwError = pkg_alter(hPMD, hPkgHandle, nAlterType, NULL);
    if(dwError == ERROR_PMD_FAIL)
    {
        dwError = 0;
        nNothingToDo = 1;
    }
    BAIL_ON_PMD_ERROR(dwError);

    if(nNothingToDo)
    {
        dwError = json_string_from_key_value(
                      "result",
                      "Nothing to do.",
                      &pszOutputJson);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = make_processed_pkgs_result(
                      pszAlterCmd,
                      ppszPackages,
                      nPkgCount,
                      &pszOutputJson);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppOutputJson = pszOutputJson;

cleanup:
    if(ppszPackages)
    {
        PMDFreeStringArrayWithCount(ppszPackages, nPkgCount);
    }
    pkg_free_cmd_args(pArgs);
    PMD_SAFE_FREE_MEMORY(pszAlterCmd);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
pkg_rest_install(
    void *pInput,
    void **ppOutputJson
    )
{
    return pkg_rest_alter(ALTER_INSTALL, pInput, ppOutputJson);
}

uint32_t
pkg_rest_update(
    void *pInput,
    void **ppOutputJson
    )
{
    return pkg_rest_alter(ALTER_UPGRADE, pInput, ppOutputJson);
}

uint32_t
pkg_rest_erase(
    void *pInput,
    void **ppOutputJson
    )
{
    return pkg_rest_alter(ALTER_ERASE, pInput, ppOutputJson);
}

uint32_t
pkg_rest_distro_sync(
    void *pInput,
    void **ppOutputJson
    )
{
    return pkg_rest_alter(ALTER_DISTRO_SYNC, pInput, ppOutputJson);
}

uint32_t
pkg_rest_downgrade(
    void *pInput,
    void **ppOutputJson
    )
{
    return pkg_rest_alter(ALTER_DOWNGRADE, pInput, ppOutputJson);
}

uint32_t
pkg_rest_reinstall(
    void *pInput,
    void **ppOutputJson
    )
{
    return pkg_rest_alter(ALTER_REINSTALL, pInput, ppOutputJson);
}

uint32_t
get_repodata_json_string(
    PTDNF_REPO_DATA pRepoData,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    json_t *pszUrlGPGKeyArray = NULL;
    int i = 0;

    if(!pRepoData || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszUrlGPGKeyArray = json_array();
    if(!pszUrlGPGKeyArray)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(; pRepoData; pRepoData = pRepoData->pNext)
    {
        json_t *pRepoObj = json_object();
        json_object_set_new(pRepoObj, "id", json_string(pRepoData->pszId));
        json_object_set_new(pRepoObj, "name", json_string(pRepoData->pszName));
        json_object_set_new(pRepoObj, "baseurl", json_string(pRepoData->pszBaseUrl));
        json_object_set_new(pRepoObj, "gpgkey", pszUrlGPGKeyArray);
        if (pRepoData->ppszUrlGPGKeys != NULL)
        {
            for(i = 0; pRepoData->ppszUrlGPGKeys[i]; i++)
            {
                json_array_append_new(pszUrlGPGKeyArray, json_string(pRepoData->ppszUrlGPGKeys[i]));
            }
        }
        json_object_set_new(pRepoObj, "metadata_expire", json_integer(0));
        json_object_set_new(pRepoObj, "skip_if_unavailable", json_boolean(pRepoData->nSkipIfUnavailable));
        json_object_set_new(pRepoObj, "enabled", json_boolean(pRepoData->nEnabled));
        json_object_set_new(pRepoObj, "gpgcheck", json_boolean(pRepoData->nGPGCheck));
        json_array_append_new(pRoot, pRepoObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
get_pkginfo_json_string(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwCount,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    uint32_t nIndex = 0;

    if(!pPkgInfo || dwCount == 0 || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(nIndex = 0; nIndex < dwCount; ++nIndex, ++pPkgInfo)
    {
        PTDNF_PKG_INFO pInfo = pPkgInfo;

        json_t *pInfoObj = json_object();
        json_object_set_new(pInfoObj, "name", json_string(pInfo->pszName));
        json_object_set_new(pInfoObj, "arch", json_string(pInfo->pszArch));
        json_object_set_new(pInfoObj, "epoch", json_integer(pInfo->dwEpoch));
        json_object_set_new(pInfoObj, "version", json_string(pInfo->pszVersion));
        json_object_set_new(pInfoObj, "release", json_string(pInfo->pszRelease));
        json_object_set_new(pInfoObj, "install_size", json_string(pInfo->pszFormattedSize));
        json_object_set_new(pInfoObj, "reponame", json_string(pInfo->pszRepoName));
        json_object_set_new(pInfoObj, "summary", json_string(pInfo->pszSummary));
        json_object_set_new(pInfoObj, "url", json_string(pInfo->pszURL));
        json_object_set_new(pInfoObj, "license", json_string(pInfo->pszLicense));
        json_object_set_new(pInfoObj, "description", json_string(pInfo->pszDescription));
        json_array_append_new(pRoot, pInfoObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
pkg_json_get_alter_args(
    const char *pszAlterCmd,
    const char **ppszPackages,
    int nPkgCount,
    PTDNF_CMD_ARGS *ppArgs
    )
{
    uint32_t dwError = 0;
    PTDNF_CMD_ARGS pArgs = NULL;
    char **ppszCmds = NULL;
    int i = 0;
    int nCmdCount = 0;

    if(IsNullOrEmptyString(pszAlterCmd) || !ppArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    //For commands that does not require args, nPkgCount will be 0.
    nCmdCount = nPkgCount + 1;
    dwError = PMDAllocateMemory(sizeof(char **) * (nCmdCount),
                                (void **)&ppszCmds);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszAlterCmd, &ppszCmds[0]);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 1; i < nCmdCount; ++i)
    {
        dwError = PMDAllocateString(ppszPackages[i-1], &ppszCmds[i]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_rest_get_cmd_args((const char **)ppszCmds,
                                    nCmdCount,
                                    &pArgs);
    BAIL_ON_PMD_ERROR(dwError);

    *ppArgs = pArgs;

cleanup:
    if(ppszCmds)
    {
        PMDFreeStringArrayWithCount(ppszCmds, nPkgCount + 1);
    }
    return dwError;

error:
    if(ppArgs)
    {
        *ppArgs = NULL;
    }
    goto cleanup;
}

uint32_t
pkg_json_get_array(
    const char *pszInputJson,
    const char *pszName,
    char ***pppszStrings,
    int *pnCount
    )
{
    uint32_t dwError = 0;
    char *pszStrings = NULL;
    char *pszCommaSeparatedStrings = NULL;
    char **ppszStrings = NULL;
    int nCount = 0;
    json_t *pJson = NULL;
    char *pszPkgs = NULL;

    if(IsNullOrEmptyString(pszInputJson) ||
       IsNullOrEmptyString(pszName) ||
       !pppszStrings ||
       !pnCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, pszName, &pszStrings);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = string_replace(pszStrings,
                             REST_COMMA,
                             ",",
                             &pszCommaSeparatedStrings);
    if(dwError == ENOENT)
    {
        dwError = PMDAllocateString(pszStrings, &pszCommaSeparatedStrings);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = make_array_from_string(pszCommaSeparatedStrings,
                                     ",",
                                     &ppszStrings,
                                     &nCount);
    BAIL_ON_PMD_ERROR(dwError);

    *pppszStrings = ppszStrings;
    *pnCount = nCount;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszStrings);
    PMD_SAFE_FREE_MEMORY(pszCommaSeparatedStrings);
    return dwError;

error:
    if(pppszStrings)
    {
        *pppszStrings = NULL;
    }
    if(pnCount)
    {
        *pnCount = 0;
    }
    goto cleanup;
}

uint32_t
pkg_get_cmd_string(
    TDNF_ALTERTYPE nAlterType,
    char ** ppszAlterCmd
    )
{
    uint32_t dwError = 0;
    char *pszAlterCmd = NULL;

    if(nAlterType == ALTER_INSTALL)
    {
        dwError = PMDAllocateString("install", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_UPGRADE)
    {
        dwError = PMDAllocateString("update", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_ERASE)
    {
        dwError = PMDAllocateString("erase", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_DOWNGRADE)
    {
        dwError = PMDAllocateString("downgrade", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_REINSTALL)
    {
        dwError = PMDAllocateString("reinstall", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_DISTRO_SYNC)
    {
        dwError = PMDAllocateString("distro-sync", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        nAlterType = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszAlterCmd = pszAlterCmd;
cleanup:
    return dwError;

error:
    if(ppszAlterCmd)
    {
        *ppszAlterCmd = NULL;
    }
    goto cleanup;
}
