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

void
usermgmt_free_rpc_users(
    PPMD_RPC_USER_ARRAY pRpcUsers
    )
{
    uint32_t dwIndex = 0;
    if(!pRpcUsers)
    {
        return;
    }
    for(dwIndex = 0; dwIndex < pRpcUsers->dwCount; ++dwIndex)
    {
        if(pRpcUsers->pUsers)
        {
            PPMD_RPC_USER pRpcUser = &pRpcUsers->pUsers[dwIndex];
            PMDRpcClientFreeMemory(pRpcUser->pwszName);
            PMDRpcClientFreeMemory(pRpcUser->pwszRealName);
            PMDRpcClientFreeMemory(pRpcUser->pwszHomeDir);
            PMDRpcClientFreeMemory(pRpcUser->pwszShell);
        }
    }
    PMDRpcClientFreeMemory(pRpcUsers->pUsers);
    PMDRpcClientFreeMemory(pRpcUsers);
}

uint32_t
usermgmt_convert_users(
    PPMD_RPC_USER_ARRAY pRpcUsers,
    PPMD_USER *ppUsers
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    PPMD_USER pUsers = NULL;
    PPMD_USER pUser = NULL;

    if(!pRpcUsers || !ppUsers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwCount = pRpcUsers->dwCount;
    if(dwCount == 0 || !pRpcUsers->pUsers)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(dwIndex = 0; dwIndex < dwCount; ++dwIndex)
    {
        PPMD_RPC_USER pRpcUser = &pRpcUsers->pUsers[dwIndex];

        dwError = PMDAllocateMemory(sizeof(PMD_USER), (void **)&pUser);
        BAIL_ON_PMD_ERROR(dwError);

        pUser->nUID = pRpcUser->nUID;
        pUser->nGID = pRpcUser->nGID;

        dwError = PMDAllocateStringAFromW(pRpcUser->pwszName,
                                          &pUser->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(pRpcUser->pwszRealName,
                                          &pUser->pszRealName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(pRpcUser->pwszHomeDir,
                                          &pUser->pszHomeDir);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(pRpcUser->pwszShell,
                                          &pUser->pszShell);
        BAIL_ON_PMD_ERROR(dwError);

        pUser->pNext = pUsers;
        pUsers = pUser;
        pUser = NULL;
    }

    *ppUsers = pUsers;

cleanup:
    usermgmt_free_rpc_users(pRpcUsers);
    return dwError;

error:
    if(ppUsers)
    {
        *ppUsers = NULL;
    }
    usermgmt_free_user(pUsers);
    usermgmt_free_user(pUser);
    goto cleanup;
}

void
usermgmt_free_rpc_groups(
    PPMD_RPC_GROUP_ARRAY pRpcGroups
    )
{
    uint32_t dwIndex = 0;
    if(!pRpcGroups)
    {
        return;
    }
    for(dwIndex = 0; dwIndex < pRpcGroups->dwCount; ++dwIndex)
    {
        if(pRpcGroups->pGroups)
        {
            PPMD_RPC_GROUP pRpcGroup = &pRpcGroups->pGroups[dwIndex];
            PMDRpcClientFreeMemory(pRpcGroup->pwszName);
        }
    }
    PMDRpcClientFreeMemory(pRpcGroups->pGroups);
    PMDRpcClientFreeMemory(pRpcGroups);
}

uint32_t
usermgmt_convert_groups(
    PPMD_RPC_GROUP_ARRAY pRpcGroups,
    PPMD_GROUP *ppGroups
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t dwIndex = 0;
    PPMD_GROUP pGroups = NULL;
    PPMD_GROUP pGroup = NULL;

    if(!pRpcGroups || !ppGroups)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwCount = pRpcGroups->dwCount;
    if(dwCount == 0 || !pRpcGroups->pGroups)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(dwIndex = 0; dwIndex < dwCount; ++dwIndex)
    {
        PPMD_RPC_GROUP pRpcGroup = &pRpcGroups->pGroups[dwIndex];

        dwError = PMDAllocateMemory(sizeof(PMD_GROUP), (void **)&pGroup);
        BAIL_ON_PMD_ERROR(dwError);

        pGroup->nGID = pRpcGroup->nGID;

        dwError = PMDAllocateStringAFromW(pRpcGroup->pwszName,
                                          &pGroup->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        pGroup->pNext = pGroups;
        pGroups = pGroup;
        pGroup = NULL;
    }

    *ppGroups = pGroups;

cleanup:
    usermgmt_free_rpc_groups(pRpcGroups);
    return dwError;

error:
    if(ppGroups)
    {
        *ppGroups = NULL;
    }
    usermgmt_free_group(pGroups);
    usermgmt_free_group(pGroup);
    goto cleanup;
}
