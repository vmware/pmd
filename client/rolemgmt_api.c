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
                      pRoleArray->pRoles[i].pwszId,
                      &pRole->pszId);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDAllocateStringAFromW(
                      pRoleArray->pRoles[i].pwszName,
                      &pRole->pszName);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDAllocateStringAFromW(
                      pRoleArray->pRoles[i].pwszDescription,
                      &pRole->pszDescription);
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
    PMDRpcClientFreeMemory(pRoleArray);
    return dwError;

error:
    if(ppRoles)
    {
        *ppRoles = NULL;
    }
    rolemgmt_free_roles(pRoles);
    rolemgmt_free_roles(pRole);
    goto cleanup;
}

uint32_t
rolemgmt_get_role_version(
    PPMDHANDLE hHandle,
    const char *pszName,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    wstring_t pwszVersion = NULL;
    wstring_t pwszName = NULL;

    if(!hHandle || IsNullOrEmptyString(pszName) || !ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(rolemgmt_rpc_role_version(hHandle->hRpc, pwszName, &pwszVersion),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszVersion,
                  &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
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
rolemgmt_get_prereqs(
    PPMDHANDLE hHandle,
    const char *pszName,
    PMD_ROLE_OPERATION nOperation,
    PPMD_ROLE_PREREQ *ppPrereqs,
    uint32_t *pdwPrereqCount
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    wstring_t pwszName = NULL;
    PPMD_RPC_ROLEMGMT_PREREQ_ARRAY pPrereqArray = NULL;
    PPMD_ROLE_PREREQ pPrereqs = NULL;
    uint32_t dwPrereqCount = 0;

    if(!hHandle || IsNullOrEmptyString(pszName) || !ppPrereqs || !pdwPrereqCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(rolemgmt_rpc_role_get_prereqs(
               hHandle->hRpc,
               pwszName,
               nOperation,
               &pPrereqArray),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwPrereqCount = pPrereqArray ? pPrereqArray->dwCount : 0;
    if(!dwPrereqCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMD_ROLE_PREREQ) * dwPrereqCount,
                  (void **)&pPrereqs);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0; i < dwPrereqCount; ++i)
    {
        dwError = PMDAllocateStringAFromW(
                      pPrereqArray->pPrereqs[i].pwszName,
                      &pPrereqs[i].pszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                      pPrereqArray->pPrereqs[i].pwszDescription,
                      &pPrereqs[i].pszDescription);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppPrereqs = pPrereqs;
    *pdwPrereqCount = dwPrereqCount;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    if(ppPrereqs)
    {
        *ppPrereqs = NULL;
    }
    goto cleanup;
}

uint32_t
rolemgmt_alter(
    PPMDHANDLE hHandle,
    const char *pszName,
    int nOperation,
    const char *pszConfigJson,
    char **ppszTaskUUID
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;
    wstring_t pwszTaskUUID = NULL;
    wstring_t pwszConfigJson = NULL;
    char *pszTaskUUID = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszName) ||
       !ppszTaskUUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(nOperation == ROLE_OPERATION_ENABLE &&
       IsNullOrEmptyString(pszConfigJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pszConfigJson))
    {
        pszConfigJson = "{}";
    }


    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(
                  pszConfigJson,
                  &pwszConfigJson);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(rolemgmt_rpc_role_alter(
               hHandle->hRpc,
               pwszName,
               nOperation,
               pwszConfigJson,
               &pwszTaskUUID
               ),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszTaskUUID,
                  &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszTaskUUID = pszTaskUUID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    PMD_SAFE_FREE_MEMORY(pwszConfigJson);
    PMDRpcClientFreeStringW(pwszTaskUUID);
    return dwError;

error:
    if(ppszTaskUUID)
    {
        *ppszTaskUUID = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszTaskUUID);
    goto cleanup;
}

uint32_t
rolemgmt_get_status(
    PPMDHANDLE hHandle,
    const char *pszName,
    const char *pszTaskUUID,
    PMD_ROLE_STATUS *pnStatus
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;
    wstring_t pwszTaskUUID = NULL;
    RPC_ROLE_STATUS nStatus = ROLE_STATUS_NONE;

    if(!hHandle ||
       IsNullOrEmptyString(pszName) ||
       IsNullOrEmptyString(pszTaskUUID) ||
       !pnStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(
                  pszTaskUUID,
                  &pwszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(rolemgmt_rpc_role_get_status(
               hHandle->hRpc,
               pwszName,
               pwszTaskUUID,
               &nStatus),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    *pnStatus = nStatus;

cleanup:
    return dwError;

error:
    if(pnStatus)
    {
        dwError = ROLE_STATUS_NONE;
    }
    goto cleanup;
}

uint32_t
rolemgmt_get_log(
    PPMDHANDLE hHandle,
    const char *pszTaskUUID,
    uint32_t dwOffset,
    uint32_t dwEntriesToFetch,
    PPMD_ROLEMGMT_TASK_LOG *ppTaskLogs,
    uint32_t *pdwTaskLogCount
    )
{
    uint32_t dwError = 0;
    uint32_t dwTaskLogCount = 0;
    uint32_t i = 0;
    wstring_t pwszTaskUUID = NULL;
    PPMD_RPC_ROLEMGMT_TASK_LOG_ARRAY pTaskLogArray = NULL;
    PPMD_ROLEMGMT_TASK_LOG pTaskLogs = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszTaskUUID) ||
       !ppTaskLogs ||
       !pdwTaskLogCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszTaskUUID,
                  &pwszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(rolemgmt_rpc_role_get_log(
               hHandle->hRpc,
               pwszTaskUUID,
               dwOffset,
               dwEntriesToFetch,
               &pTaskLogArray),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwTaskLogCount = pTaskLogArray ? pTaskLogArray->dwCount : 0;
    if(!dwTaskLogCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMD_ROLEMGMT_TASK_LOG) * dwTaskLogCount,
                  (void **)&pTaskLogs);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0; i < dwTaskLogCount; ++i)
    {
        pTaskLogs[i].tStamp = pTaskLogArray->pTaskLogs[i].tStamp;
        dwError = PMDAllocateStringAFromW(
                      pTaskLogArray->pTaskLogs[i].pwszLog,
                      &pTaskLogs[i].pszLog);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppTaskLogs = pTaskLogs;
    *pdwTaskLogCount = dwTaskLogCount;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszTaskUUID);
    return dwError;

error:
    if(ppTaskLogs)
    {
        *ppTaskLogs = NULL;
    }
    if(pdwTaskLogCount)
    {
        *pdwTaskLogCount = 0;
    }
    goto cleanup;
}
