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
rolemgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    wstring_t pwszVersion = NULL;

    if(!hHandle || !ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(rolemgmt_rpc_version(hHandle->hRpc, &pwszVersion), dwError);
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
    goto cleanup;
}

uint32_t
rolemgmt_get_roles(
    PPMDHANDLE hHandle,
    PPMD_ROLEMGMT_ROLE *ppRoles
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_ROLEMGMT_ROLE_ARRAY pRoleArray = NULL;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    PPMD_ROLEMGMT_ROLE pTail = NULL;
    uint32_t i = 0;

    if(!hHandle || !ppRoles)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(rolemgmt_rpc_get_roles(hHandle->hRpc, &pRoleArray), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pRoleArray || !pRoleArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < pRoleArray->dwCount; ++i)
    {
        dwError = PMDAllocateMemory(
                      sizeof(PMD_ROLEMGMT_ROLE),
                      (void **)&pRole);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                      pRoleArray->pRoles[i].pwszRole,
                      &pRole->pszRole);
        BAIL_ON_PMD_ERROR(dwError);
        if(!pTail)
        {
            pRoles = pRole;
            pTail = pRoles;
        }
        else
        {
            pTail->pNext = pRole;
            pTail = pTail->pNext;
        }
        pRole = NULL;
    }

    *ppRoles = pRoles;
cleanup:
    return dwError;

error:
    if(ppRoles)
    {
        *ppRoles = NULL;
    }
    goto cleanup;
}
