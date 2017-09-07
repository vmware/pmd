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
    wstring_t pwszVersion = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_version_w(hPMD, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
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
    unsigned32 nUID = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszName || !pnUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_userid_w(hPMD, pwszName, &nUID);
    BAIL_ON_PMD_ERROR(dwError);

    *pnUID = nUID;

cleanup:
    rpc_free_handle(hPMD);
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
    unsigned32 nGID = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszName || !pnGID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_groupid_w(hPMD, pwszName, &nGID);
    BAIL_ON_PMD_ERROR(dwError);

    *pnGID = nGID;

cleanup:
    rpc_free_handle(hPMD);
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
    PPMD_RPC_USER_ARRAY pUserArray = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppUserArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_users_w(hPMD, &pUserArray);
    BAIL_ON_PMD_ERROR(dwError);

    *ppUserArray = pUserArray;

cleanup:
    rpc_free_handle(hPMD);
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
    PPMD_RPC_GROUP_ARRAY pGroupArray = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppGroupArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_get_groups_w(hPMD, &pGroupArray);
    BAIL_ON_PMD_ERROR(dwError);

    *ppGroupArray = pGroupArray;

cleanup:
    rpc_free_handle(hPMD);
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
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_add_user_w(hPMD, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
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
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = usermgmt_delete_user_w(hPMD, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
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
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_add_group_w(hPMD, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
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
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(USERMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = usermgmt_delete_group_w(hPMD, pwszName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    goto cleanup;
}
