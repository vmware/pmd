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
    int nLocked = 0;

    if(!hBinding || !ppRpcRoleArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gRoleMgmtEnv.mutexEnv);
    nLocked = 1;

    pRoleMgmtRole = gRoleMgmtEnv.pRoles;
    if(!pRoleMgmtRole)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

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
                      pRole->pszId,
                      &pRpcRoles[i].pwszId);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateWFromA(
                      pRole->pszName,
                      &pRpcRoles[i].pwszName);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateWFromA(
                      pRole->pszDescription,
                      &pRpcRoles[i].pwszDescription);
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRpcRoleArray->pRoles = pRpcRoles;

    *ppRpcRoleArray = pRpcRoleArray;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gRoleMgmtEnv.mutexEnv);
    }
    return dwError;

error:
    if(ppRpcRoleArray)
    {
        *ppRpcRoleArray = NULL;
    }
    PMDRpcServerFreeMemory(pRpcRoleArray);
    goto cleanup;
}

unsigned32
rolemgmt_rpc_role_version(
    handle_t hBinding,
    wstring_t pwszName,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;
    char* pszName = NULL;
    wstring_t pwszVersion = NULL;

    if(!hBinding || !pwszName || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_role_version(pszName, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
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
rolemgmt_rpc_role_get_prereqs(
    handle_t hBinding,
    wstring_t pwszName,
    RPC_ROLE_OPERATION nOperation,
    PPMD_RPC_ROLEMGMT_PREREQ_ARRAY *ppPrereqArray
    )
{
    uint32_t dwError = 0;
    uint32_t dwPrereqCount = 0;
    char *pszName = NULL;
    PPMD_ROLE_PREREQ pPrereqs = NULL;
    PPMD_RPC_ROLEMGMT_PREREQ_ARRAY pPrereqArray = NULL;
    if(!hBinding || !pwszName || !ppPrereqArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_role_get_prereqs(
                  pszName,
                  nOperation,
                  &pPrereqs,
                  &dwPrereqCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_ROLEMGMT_PREREQ_ARRAY),
                  (void **)&pPrereqArray);
    BAIL_ON_PMD_ERROR(dwError);

    pPrereqArray->dwCount = dwPrereqCount;

    if(dwPrereqCount > 0)
    {
        uint32_t i = 0;
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(PMD_RPC_ROLEMGMT_PREREQ) * dwPrereqCount,
                      (void **)&pPrereqArray->pPrereqs);
        BAIL_ON_PMD_ERROR(dwError);

        for(i = 0; i < dwPrereqCount; ++i)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          pPrereqs[i].pszName,
                          &pPrereqArray->pPrereqs[i].pwszName);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = PMDRpcServerAllocateWFromA(
                          pPrereqs[i].pszDescription,
                          &pPrereqArray->pPrereqs[i].pwszDescription);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppPrereqArray = pPrereqArray;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppPrereqArray)
    {
        *ppPrereqArray = NULL;
    }
    rolemgmt_rpc_role_free_prereq_array(pPrereqArray);
    goto cleanup;
}

unsigned32
rolemgmt_rpc_role_get_status(
    handle_t hBinding,
    wstring_t pwszName,
    wstring_t pwszTaskUUID,
    RPC_ROLE_STATUS *pnStatus
    )
{
    uint32_t dwError = 0;
    PMD_ROLE_STATUS nStatus = RPC_ROLE_STATUS_NONE;
    char *pszName = NULL;
    char *pszTaskUUID = NULL;
    if(!hBinding || !pwszName || !pwszTaskUUID || !pnStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszTaskUUID, &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_get_status(pszName, pszTaskUUID, &nStatus);
    BAIL_ON_PMD_ERROR(dwError);

    *pnStatus = nStatus;
cleanup:
    return dwError;

error:
    if(pnStatus)
    {
        *pnStatus = RPC_ROLE_STATUS_NONE;
    }
    goto cleanup;
}

unsigned32
rolemgmt_rpc_role_alter_with_config_json(
    handle_t hBinding,
    wstring_t pwszName,
    RPC_ROLE_OPERATION nOperation,
    wstring_t pwszConfigJson,
    wstring_t* ppwszTaskUUID
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    char *pszConfigJson = NULL;
    wstring_t pwszTaskUUID = NULL;
    char *pszTaskUUID = NULL;

    if(!hBinding || !pwszName || !pwszConfigJson || !ppwszTaskUUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszConfigJson, &pszConfigJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_role_alter_with_config_json(
                  pszName,
                  nOperation,
                  pszConfigJson,
                  &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszTaskUUID, &pwszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszTaskUUID = pwszTaskUUID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppwszTaskUUID)
    {
        *ppwszTaskUUID = NULL;
    }
    if(pwszTaskUUID)
    {
        PMDRpcServerFreeMemory(pwszTaskUUID);
    }
    goto cleanup;
}

unsigned32
rolemgmt_rpc_role_get_log(
    handle_t hBinding,
    wstring_t pwszTaskUUID,
    unsigned32 nOffset,
    unsigned32 nEntriesToFetch,
    PPMD_RPC_ROLEMGMT_TASK_LOG_ARRAY *ppTaskLogArray
    )
{
    uint32_t dwError = 0;
    char *pszTaskUUID = NULL;
    PPMD_RPC_ROLEMGMT_TASK_LOG_ARRAY pTaskLogArray = NULL;
    PPMD_PLUGIN_TASK_LOG pTaskLogs = NULL;
    PPMD_PLUGIN_TASK_LOG pTemp = NULL;
    uint32_t i = 0;

    if(!hBinding || !pwszTaskUUID || !ppTaskLogArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(nEntriesToFetch == 0)
    {
        dwError = ERROR_PMD_NOTHING_TO_DO;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszTaskUUID, &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_get_logs(pszTaskUUID,
                                nOffset,
                                nEntriesToFetch,
                                &pTaskLogs);
    BAIL_ON_PMD_ERROR(dwError);

    for(pTemp = pTaskLogs, i = 0;
        pTemp && i < nEntriesToFetch;
        pTemp = pTemp->pNext, ++i);

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_ROLEMGMT_TASK_LOG_ARRAY),
                  (void **)&pTaskLogArray);
    BAIL_ON_PMD_ERROR(dwError);

    pTaskLogArray->dwCount = i;

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_ROLEMGMT_TASK_LOG) * i,
                  (void **)&pTaskLogArray->pTaskLogs);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0, pTemp = pTaskLogs; i < pTaskLogArray->dwCount; ++i)
    {
        dwError = PMDRpcServerAllocateWFromA(
                      pTemp->pszLog,
                      &pTaskLogArray->pTaskLogs[i].pwszLog);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppTaskLogArray = pTaskLogArray;
cleanup:
    return dwError;

error:
    if(ppTaskLogArray)
    {
        *ppTaskLogArray = NULL;
    }
    rolemgmt_rpc_role_free_task_log_array(pTaskLogArray);
    goto cleanup;
}

void
rolemgmt_rpc_role_free_task_log_array(
    PPMD_RPC_ROLEMGMT_TASK_LOG_ARRAY pTaskLogArray
    )
{
    uint32_t i = 0;
    if(!pTaskLogArray)
    {
        return;
    }
    for(i = 0; i < pTaskLogArray->dwCount; ++i)
    {
        PPMD_RPC_ROLEMGMT_TASK_LOG pTaskLog = &pTaskLogArray->pTaskLogs[i];
        PMD_RPCSRV_SAFE_FREE_MEMORY(pTaskLog->pwszLog);
    }
    PMD_RPCSRV_SAFE_FREE_MEMORY(pTaskLogArray->pTaskLogs);
    PMDRpcServerFreeMemory(pTaskLogArray);
}

void
rolemgmt_rpc_role_free_prereq_array(
    PPMD_RPC_ROLEMGMT_PREREQ_ARRAY pPrereqArray
    )
{
    uint32_t i = 0;
    if(!pPrereqArray)
    {
        return;
    }
    for(i = 0; i < pPrereqArray->dwCount; ++i)
    {
        PPMD_RPC_ROLEMGMT_PREREQ pPrereq = &pPrereqArray->pPrereqs[i];
        PMD_RPCSRV_SAFE_FREE_MEMORY(pPrereq->pwszName);
        PMD_RPCSRV_SAFE_FREE_MEMORY(pPrereq->pwszDescription);
    }
    PMD_RPCSRV_SAFE_FREE_MEMORY(pPrereqArray->pPrereqs);
    PMDRpcServerFreeMemory(pPrereqArray);
}
