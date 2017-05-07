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
rolemgmt_rpc_version(
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

    dwError = pmd_rolemgmt_get_version(&pszVersion);
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
    PMD_SAFE_FREE_MEMORY(pwszVersion);
    goto cleanup;
}

unsigned32
rolemgmt_rpc_get_roles(
    handle_t hBinding,
    PPMD_RPC_ROLEMGMT_ROLE_ARRAY *ppRpcRoleArray
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_ROLE pRoleMgmtRole = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    PPMD_RPC_ROLEMGMT_ROLE_ARRAY pRpcRoleArray = NULL;
    PPMD_RPC_ROLEMGMT_ROLE pRpcRoles = NULL;
    uint32_t dwCount = 0;
    int i = 0;

    if(!hBinding || !ppRpcRoleArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rolemgmt_get_roles(&pRoleMgmtRole);
    BAIL_ON_PMD_ERROR(dwError);

    for(pRole = pRoleMgmtRole; pRole; pRole = pRole->pNext)
    {
        ++dwCount;
    }

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_ROLEMGMT_ROLE_ARRAY),
                  (void **)&pRpcRoleArray);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcRoleArray->dwCount = dwCount;

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_ROLEMGMT_ROLE) * dwCount,
                  (void **)&pRpcRoles);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0, pRole = pRoleMgmtRole; pRole; pRole = pRole->pNext, ++i)
    {
        dwError = PMDRpcServerAllocateWFromA(
                      pRole->pszRole,
                      &pRpcRoles[i].pwszRole);
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRpcRoleArray->pRoles = pRpcRoles;

    *ppRpcRoleArray = pRpcRoleArray;

cleanup:
    return dwError;

error:
    if(ppRpcRoleArray)
    {
        *ppRpcRoleArray = NULL;
    }
    PMDRpcServerFreeMemory(ppRpcRoleArray);
    goto cleanup;
}
