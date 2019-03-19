/*
 * Copyright © 2019 VMware, Inc.  All Rights Reserved.
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
rpmostree_rpc_version(
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

    pszVersion = PACKAGE_VERSION;
    if(IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pwszVersion);
    goto cleanup;
}

unsigned32
rpmostree_rpc_server_info(
    handle_t hBinding,
    PPMD_RPMOSTREE_SERVER_INFO* ppInfo
    )
{
    uint32_t dwError = 0;
    PPMD_CONFIG pConfig = NULL;
    PPMD_RPMOSTREE_SERVER_INFO pInfo = NULL;
    
    if(!hBinding || !ppInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = pmd_read_config(
                  PMD_CONFIG_FILE_NAME,
                  PMD_CONFIG_MAIN_GROUP,
                  &pConfig);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(
        sizeof(PMD_RPMOSTREE_SERVER_INFO),
        (void**)&pInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pInfo->dwServerType = pConfig->nServerType;

    dwError = PMDRpcServerAllocateWFromA(
                  pConfig->pszServerUrl,
                  &pInfo->pwszServerUrl);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(
                  pConfig->pszCurrentHash,
                  &pInfo->pwszCurrentHash);
    BAIL_ON_PMD_ERROR(dwError);

    *ppInfo = pInfo;

cleanup:
    if(pConfig)
    {
        pmd_free_config(pConfig);
    }
    return dwError;

error:
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    goto cleanup;
}

unsigned32
rpmostree_rpc_client_info(
    handle_t hBinding,
    PPMD_RPMOSTREE_CLIENT_INFO* ppInfo
    )
{
    uint32_t dwError = 0;
    PPMD_CONFIG pConfig = NULL;
    PPMD_RPMOSTREE_CLIENT_INFO pInfo = NULL;

    if(!hBinding || !ppInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = pmd_read_config(
                  PMD_CONFIG_FILE_NAME,
                  PMD_CONFIG_MAIN_GROUP,
                  &pConfig);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(
        sizeof(PMD_RPMOSTREE_CLIENT_INFO),
        (void**)&pInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pInfo->dwServerType = pConfig->nServerType;

    dwError = PMDRpcServerAllocateWFromA(
                  pConfig->pszComposeServer,
                  &pInfo->pwszComposeServer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(
                  pConfig->pszCurrentHash,
                  &pInfo->pwszCurrentHash);
    BAIL_ON_PMD_ERROR(dwError);

    *ppInfo = pInfo;
cleanup:
    if(pConfig)
    {
        pmd_free_config(pConfig);
    }
    return dwError;

error:
    if(ppInfo)
    {
        *ppInfo = NULL;
    }
    goto cleanup;
}

unsigned32
rpmostree_rpc_client_syncto(
    handle_t hBinding,
    wstring_t pwszHash
    )
{
    uint32_t dwError = 0;
    char* pszHash = NULL;
    
    if(!hBinding || !pwszHash)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = PMDAllocateStringAFromW(pwszHash, &pszHash);
    BAIL_ON_PMD_ERROR(dwError);

    printf("Syncing to hash: %s\n", pszHash);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszHash);
    return dwError;

error:
    goto cleanup;
}
