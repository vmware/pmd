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
usermgmt_get_version_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszVersion
    )
{
    uint32_t dwError = 0;
    wstring_t pwszVersion = NULL;

    if(!hHandle || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_version(hHandle->hRpc, &pwszVersion),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_version(hHandle->hRpc, &pwszVersion), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    return dwError;

error:
    PMDRpcClientFreeStringW(pwszVersion);
    goto cleanup;
}

uint32_t
usermgmt_get_version(
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

    dwError = usermgmt_get_version_w(hHandle, &pwszVersion);
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
usermgmt_get_userid_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName,
    uint32_t *pnUID
    )
{
    uint32_t dwError = 0;
    uint32_t nUID = 0;

    if(!hHandle || !pwszName || !pnUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_get_userid(hHandle->hRpc, pwszName, &nUID),
               dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_get_userid(hHandle->hRpc, pwszName, &nUID),
               dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pnUID = nUID;

cleanup:
    return dwError;

error:
    if(pnUID)
    {
        *pnUID = 0;
    }
    goto cleanup;
}

uint32_t
usermgmt_get_userid(
    PPMDHANDLE hHandle,
    const char *pszName,
    uint32_t *pnUID
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;
    uint32_t nUID = 0;

    if(!hHandle || IsNullOrEmptyString(pszName) || !pnUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_userid_w(hHandle, pwszName, &nUID);
    BAIL_ON_PMD_ERROR(dwError);

    *pnUID = nUID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    if(pnUID)
    {
        *pnUID = 0;
    }
    goto cleanup;
}

uint32_t
usermgmt_get_groupid_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName,
    uint32_t *pnGID
    )
{
    uint32_t dwError = 0;
    uint32_t nGID = 0;

    if(!hHandle || !pwszName || !pnGID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_get_groupid(hHandle->hRpc, pwszName, &nGID),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_get_groupid(hHandle->hRpc, pwszName, &nGID),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pnGID = nGID;

cleanup:
    return dwError;

error:
    if(pnGID)
    {
        *pnGID = 0;
    }
    goto cleanup;
}

uint32_t
usermgmt_get_groupid(
    PPMDHANDLE hHandle,
    const char *pszName,
    uint32_t *pnGID
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;
    uint32_t nGID = 0;

    if(!hHandle || IsNullOrEmptyString(pszName) || !pnGID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_groupid_w(hHandle, pwszName, &nGID);
    BAIL_ON_PMD_ERROR(dwError);

    *pnGID = nGID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    if(pnGID)
    {
        *pnGID = 0;
    }
    goto cleanup;
}

uint32_t
usermgmt_get_users_w(
    PPMDHANDLE hHandle,
    PPMD_RPC_USER_ARRAY *ppRpcUsers
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_USER_ARRAY pRpcUsers = NULL;

    if(!hHandle || !ppRpcUsers)
    {
         dwError = ERROR_PMD_INVALID_PARAMETER;
         BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_get_users(hHandle->hRpc, &pRpcUsers),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_get_users(hHandle->hRpc, &pRpcUsers), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppRpcUsers = pRpcUsers;

cleanup:
    return dwError;

error:
    if(ppRpcUsers)
    {
        *ppRpcUsers = NULL;
    }
    goto cleanup;
}

uint32_t
usermgmt_get_users(
    PPMDHANDLE hHandle,
    PPMD_USER *ppUsers
    )
{
    uint32_t dwError = 0;
    PPMD_USER pUsers = NULL;
    PPMD_RPC_USER_ARRAY pRpcUsers = NULL;

    if(!hHandle || !ppUsers)
    {
         dwError = ERROR_PMD_INVALID_PARAMETER;
         BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = usermgmt_get_users_w(hHandle, &pRpcUsers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_convert_users(pRpcUsers, &pUsers);
    BAIL_ON_PMD_ERROR(dwError);

    *ppUsers = pUsers;

cleanup:
    return dwError;

error:
    if(ppUsers)
    {
        *ppUsers = NULL;
    }
    usermgmt_free_user(pUsers);
    goto cleanup;
}

uint32_t
usermgmt_get_groups_w(
    PPMDHANDLE hHandle,
    PPMD_RPC_GROUP_ARRAY *ppRpcGroups
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_GROUP_ARRAY pRpcGroups = NULL;

    if(!hHandle || !ppRpcGroups)
    {
         dwError = ERROR_PMD_INVALID_PARAMETER;
         BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_get_groups(hHandle->hRpc, &pRpcGroups),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_get_groups(hHandle->hRpc, &pRpcGroups), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppRpcGroups = pRpcGroups;

cleanup:
    return dwError;

error:
    if(ppRpcGroups)
    {
        *ppRpcGroups = NULL;
    }
    goto cleanup;
}

uint32_t
usermgmt_get_groups(
    PPMDHANDLE hHandle,
    PPMD_GROUP *ppGroups
    )
{
    uint32_t dwError = 0;
    PPMD_GROUP pGroups = NULL;
    PPMD_RPC_GROUP_ARRAY pRpcGroups = NULL;

    if(!hHandle || !ppGroups)
    {
         dwError = ERROR_PMD_INVALID_PARAMETER;
         BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = usermgmt_get_groups_w(hHandle, &pRpcGroups);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_convert_groups(pRpcGroups, &pGroups);
    BAIL_ON_PMD_ERROR(dwError);

    *ppGroups = pGroups;

cleanup:
    return dwError;

error:
    if(ppGroups)
    {
        *ppGroups = NULL;
    }
    usermgmt_free_group(pGroups);
    goto cleanup;
}

uint32_t
usermgmt_add_user_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_add_user(hHandle->hRpc, pwszName), dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_add_user(hHandle->hRpc, pwszName), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_add_user(
    PPMDHANDLE hHandle,
    const char *pszName
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;

    if(!hHandle || IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_add_user_w(hHandle, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_delete_user_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_delete_user(hHandle->hRpc, pwszName),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_delete_user(hHandle->hRpc, pwszName), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_delete_user(
    PPMDHANDLE hHandle,
    const char *pszName
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;

    if(!hHandle || IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_delete_user_w(hHandle, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_add_group_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_add_group(hHandle->hRpc, pwszName),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_add_group(hHandle->hRpc, pwszName), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_add_group(
    PPMDHANDLE hHandle,
    const char *pszName
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;

    if(!hHandle || IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_add_group_w(hHandle, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_delete_group_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(usermgmt_privsep_rpc_delete_group(hHandle->hRpc, pwszName),
                   dwError);
    }
    else
    {
        DO_RPC(usermgmt_rpc_delete_group(hHandle->hRpc, pwszName), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_delete_group(
    PPMDHANDLE hHandle,
    const char *pszName
    )
{
    uint32_t dwError = 0;
    wstring_t pwszName = NULL;

    if(!hHandle || IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszName,
                  &pwszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_delete_group_w(hHandle, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszName);
    return dwError;

error:
    goto cleanup;
}
