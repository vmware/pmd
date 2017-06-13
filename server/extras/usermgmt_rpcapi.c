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
usermgmt_rpc_version(
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

    dwError = pmd_usermgmt_get_version(&pszVersion);
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
usermgmt_rpc_get_userid(
    handle_t hBinding,
    wstring_t pwszName,
    unsigned32 *pnUID
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    unsigned32 nUID = 0;

    if(!hBinding || !pwszName || !pnUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_usermgmt_get_userid(pszName, &nUID);
    BAIL_ON_PMD_ERROR(dwError);

    *pnUID = nUID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(pnUID)
    {
        *pnUID = 0;
    }
    goto cleanup;
}

unsigned32
usermgmt_rpc_get_groupid(
    handle_t hBinding,
    wstring_t pwszName,
    unsigned32 *pnGID
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    unsigned32 nGID = 0;

    if(!hBinding || !pwszName || !pnGID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);
    
    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_usermgmt_get_groupid(pszName, &nGID);
    BAIL_ON_PMD_ERROR(dwError);

    *pnGID = nGID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(pnGID)
    {
        *pnGID = 0;
    }
    goto cleanup;
}

unsigned32
usermgmt_rpc_get_users(
    handle_t hBinding,
    PPMD_RPC_USER_ARRAY *ppUserArray
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_USER pRpcUser = NULL;
    PPMD_RPC_USER_ARRAY pUserArray = NULL;
    PPMD_USER pUsers = NULL;
    PPMD_USER pUsersTemp  = NULL;
    wstring_t pwszTemp = NULL;
    int nCount = 0;

    if(!hBinding || !ppUserArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = pmd_usermgmt_get_users(&pUsers);
    BAIL_ON_PMD_ERROR(dwError);

    for(pUsersTemp = pUsers; pUsersTemp; pUsersTemp = pUsersTemp->pNext)
    {
        ++nCount;
    }

    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_RPC_USER_ARRAY),
                                (void **)&pUserArray);
    BAIL_ON_PMD_ERROR(dwError);

    pUserArray->dwCount = nCount;

    dwError = PMDAllocateMemory(sizeof(PMD_RPC_USER) * nCount,
                                (void **)&pUserArray->pUsers);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcUser = pUserArray->pUsers;
    pUsersTemp = pUsers;
    while(pUsersTemp)
    {
        pRpcUser->nUID = pUsersTemp->nUID;
        pRpcUser->nGID = pUsersTemp->nGID;

        dwError = PMDAllocateStringWFromA(pUsersTemp->pszName, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcUser->pwszName);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);

        dwError = PMDAllocateStringWFromA(pUsersTemp->pszRealName, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcUser->pwszRealName);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);

        dwError = PMDAllocateStringWFromA(pUsersTemp->pszHomeDir, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcUser->pwszHomeDir);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);

        dwError = PMDAllocateStringWFromA(pUsersTemp->pszShell, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcUser->pwszShell);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);

        pUsersTemp = pUsersTemp->pNext;
        pRpcUser++;
    }

    *ppUserArray = pUserArray;

cleanup:
    if(pUsers)
    {
        usermgmt_free_user(pUsers);
    }
    return dwError;

error:
    if(ppUserArray)
    {
        *ppUserArray = pUserArray;
    }
    goto cleanup;
}

unsigned32
usermgmt_rpc_get_groups(
    handle_t hBinding,
    PPMD_RPC_GROUP_ARRAY *ppGroupArray
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_GROUP pRpcGroup = NULL;
    PPMD_RPC_GROUP_ARRAY pGroupArray = NULL;
    PPMD_GROUP pGroups = NULL;
    PPMD_GROUP pGroupsTemp  = NULL;
    wstring_t pwszTemp = NULL;
    int nCount = 0;

    if(!hBinding || !ppGroupArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = pmd_usermgmt_get_groups(&pGroups);
    BAIL_ON_PMD_ERROR(dwError);

    for(pGroupsTemp = pGroups; pGroupsTemp; pGroupsTemp = pGroupsTemp->pNext)
    {
        ++nCount;
    }

    dwError = PMDAllocateMemory(sizeof(PMD_RPC_GROUP_ARRAY),
                                (void **)&pGroupArray);
    BAIL_ON_PMD_ERROR(dwError);

    pGroupArray->dwCount = nCount;

    dwError = PMDAllocateMemory(sizeof(PMD_RPC_GROUP) * nCount,
                                (void **)&pGroupArray->pGroups);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcGroup = pGroupArray->pGroups;
    pGroupsTemp = pGroups;
    while(pGroupsTemp)
    {
        pRpcGroup->nGID = pGroupsTemp->nGID;

        dwError = PMDAllocateStringWFromA(pGroupsTemp->pszName, &pwszTemp);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pRpcGroup->pwszName);
        BAIL_ON_PMD_ERROR(dwError);
        PMDFreeMemory(pwszTemp);

        pGroupsTemp = pGroupsTemp->pNext;
        pRpcGroup++;
    }

    *ppGroupArray = pGroupArray;

cleanup:
    if(pGroups)
    {
        usermgmt_free_group(pGroups);
    }
    return dwError;

error:
    if(ppGroupArray)
    {
        *ppGroupArray = pGroupArray;
    }
    goto cleanup;
}

unsigned32
usermgmt_rpc_add_user(
    handle_t hBinding,
    wstring_t pwszName
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_usermgmt_add_user(pszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    goto cleanup;
}

unsigned32
usermgmt_rpc_delete_user(
    handle_t hBinding,
    wstring_t pwszName
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_usermgmt_delete_user(pszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    goto cleanup;
}

unsigned32
usermgmt_rpc_add_group(
    handle_t hBinding,
    wstring_t pwszName
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_usermgmt_add_group(pszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    goto cleanup;
}

unsigned32
usermgmt_rpc_delete_group(
    handle_t hBinding,
    wstring_t pwszName
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = PMDAllocateStringAFromW(pwszName, &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_usermgmt_delete_group(pszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    goto cleanup;
}
