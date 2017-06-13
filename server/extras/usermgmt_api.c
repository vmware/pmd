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
pmd_usermgmt_get_version(
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString("0.1", &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_usermgmt_get_userid(
    const char *pszName,
    uint32_t *pnUID
    )
{
    uint32_t dwError = 0;
    uint32_t nUID = 0;
    int nPwdLength = 0;
    struct passwd stPwd = {0};
    char *pBuffer = NULL;
    struct passwd *pResult = NULL;

    if(IsNullOrEmptyString(pszName) || !pnUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nPwdLength = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(nPwdLength < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(nPwdLength, (void **)&pBuffer);
    BAIL_ON_PMD_ERROR(dwError);

    errno = 0;

    dwError = getpwnam_r(pszName, &stPwd, pBuffer, nPwdLength, &pResult);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pResult)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nUID = stPwd.pw_uid;
    *pnUID = nUID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pBuffer);
    return dwError;

error:
    if(pnUID)
    {
        *pnUID = 0;
    }
    goto cleanup;
}

uint32_t
pmd_usermgmt_get_groupid(
    const char *pszName,
    uint32_t *pnGID
    )
{
    uint32_t dwError = 0;
    uint32_t nGID = 0;
    int nGrpLength = 0;
    struct group stGroup = {0};
    char *pBuffer = NULL;
    struct group *pResult = NULL;

    if(IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nGrpLength = sysconf(_SC_GETGR_R_SIZE_MAX);
    if(nGrpLength < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(nGrpLength, (void **)&pBuffer);
    BAIL_ON_PMD_ERROR(dwError);

    errno = 0;

    dwError = getgrnam_r(pszName, &stGroup, pBuffer, nGrpLength, &pResult);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pResult)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nGID  = stGroup.gr_gid;
    *pnGID = nGID;

cleanup:
    PMD_SAFE_FREE_MEMORY(pBuffer);
    return dwError;

error:
    if(pnGID)
    {
        *pnGID = 0;
    }
    goto cleanup;
}

uint32_t
make_pmd_user(
    struct passwd *pPasswd,
    PPMD_USER *ppUser
    )
{
    uint32_t dwError = 0;
    PPMD_USER pUser = NULL;

    if(!pPasswd || !ppUser)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_USER), (void **)&pUser);
    BAIL_ON_PMD_ERROR(dwError);

    pUser->nUID = pPasswd->pw_uid;
    pUser->nGID = pPasswd->pw_gid;

    dwError = PMDAllocateString(pPasswd->pw_name, &pUser->pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pPasswd->pw_dir, &pUser->pszHomeDir);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pPasswd->pw_gecos, &pUser->pszRealName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pPasswd->pw_shell, &pUser->pszShell);
    BAIL_ON_PMD_ERROR(dwError);

    *ppUser = pUser;

cleanup:
    return dwError;

error:
    if(ppUser)
    {
        *ppUser = NULL;
    }
    usermgmt_free_user(pUser);
    goto cleanup;
}

uint32_t
pmd_usermgmt_get_users(
    PPMD_USER *ppUsers
    )
{
    uint32_t dwError = 0;
    PPMD_USER pUsers = NULL;
    PPMD_USER pUser = NULL;
    int nPwdLength = 0;
    char *pBuffer = NULL;

    if(!ppUsers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nPwdLength = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(nPwdLength < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(nPwdLength, (void **)&pBuffer);
    BAIL_ON_PMD_ERROR(dwError);

    setpwent();
    while(1)
    {
        struct passwd stPasswd = {0};
        struct passwd *pPasswd = NULL;

        dwError = getpwent_r(&stPasswd, pBuffer, nPwdLength, &pPasswd);
        if(dwError == ENOENT)
        {
            dwError = 0;
            break;
        }
        BAIL_ON_PMD_ERROR(dwError);

        if(!pPasswd)
        {
            dwError = ERROR_PMD_NO_DATA;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = make_pmd_user(pPasswd, &pUser);
        BAIL_ON_PMD_ERROR(dwError);

        pUser->pNext = pUsers;
        pUsers = pUser;
        pUser = NULL;
    }

    *ppUsers = pUsers;

cleanup:
    endpwent();
    PMD_SAFE_FREE_MEMORY(pBuffer);
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
make_pmd_group(
    struct group *pStGroup,
    PPMD_GROUP *ppGroup
    )
{
    uint32_t dwError = 0;
    PPMD_GROUP pGroup = NULL;

    if(!pStGroup || !ppGroup)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_GROUP), (void **)&pGroup);
    BAIL_ON_PMD_ERROR(dwError);

    pGroup->nGID = pStGroup->gr_gid;

    dwError = PMDAllocateString(pStGroup->gr_name, &pGroup->pszName);
    BAIL_ON_PMD_ERROR(dwError);

    *ppGroup = pGroup;

cleanup:
    return dwError;

error:
    if(ppGroup)
    {
        *ppGroup = NULL;
    }
    usermgmt_free_group(pGroup);
    goto cleanup;
}

uint32_t
pmd_usermgmt_get_groups(
    PPMD_GROUP *ppGroups
    )
{
    uint32_t dwError = 0;
    PPMD_GROUP pGroups = NULL;
    PPMD_GROUP pGroup = NULL;
    int nGrpLength = 0;
    char *pBuffer = NULL;

    if(!ppGroups)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nGrpLength = sysconf(_SC_GETGR_R_SIZE_MAX);
    if(nGrpLength < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(nGrpLength, (void **)&pBuffer);
    BAIL_ON_PMD_ERROR(dwError);

    setgrent();
    while(1)
    {
        struct group stGroup = {0};
        struct group *pStGroup = NULL;

        dwError = getgrent_r(&stGroup, pBuffer, nGrpLength, &pStGroup);
        if(dwError == ENOENT)
        {
            dwError = 0;
            break;
        }
        BAIL_ON_PMD_ERROR(dwError);

        if(!pStGroup)
        {
            dwError = ERROR_PMD_NO_DATA;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = make_pmd_group(pStGroup, &pGroup);
        BAIL_ON_PMD_ERROR(dwError);

        pGroup->pNext = pGroups;
        pGroups = pGroup;
        pGroup = NULL;
    }

    *ppGroups = pGroups;

cleanup:
    endgrent();
    PMD_SAFE_FREE_MEMORY(pBuffer);
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
pmd_usermgmt_add_user(
    char *pszName
    )
{
    uint32_t dwError = 0;
    char *pszCmd = NULL;

    if(IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(&pszCmd, "useradd %s", pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = run_cmd(pszCmd, pszCmd);
    if(dwError > 0)
    {
        dwError = ERROR_PMD_ALREADY_EXISTS;
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCmd);
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_usermgmt_delete_user(
    char *pszName
    )
{
    uint32_t dwError = 0;
    char *pszCmd = NULL;

    if(IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(&pszCmd, "userdel %s", pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = run_cmd(pszCmd, pszCmd);
    if(dwError > 0)
    {
        dwError = ERROR_PMD_NO_DATA;
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCmd);
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_usermgmt_add_group(
    char *pszName
    )
{
    uint32_t dwError = 0;
    char *pszCmd = NULL;
    if(IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(&pszCmd, "groupadd %s", pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = run_cmd(pszCmd, pszCmd);
    if(dwError > 0)
    {
        dwError = ERROR_PMD_ALREADY_EXISTS;
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCmd);
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_usermgmt_delete_group(
    char *pszName
    )
{
    uint32_t dwError = 0;
    char *pszCmd = NULL;
    if(IsNullOrEmptyString(pszName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(&pszCmd, "groupdel %s", pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = run_cmd(pszCmd, pszCmd);
    if(dwError > 0)
    {
        dwError = ERROR_PMD_NO_DATA;
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCmd);
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_usermgmt_get_groups_for_user(
    uint32_t nUserID,
    char ***pppszGroups,
    int *pnGroupCount
    )
{
    uint32_t dwError = 0;
    if(!nUserID || !pppszGroups || !pnGroupCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}
    
uint32_t
pmd_usermgmt_get_users_for_group(
    uint32_t nGroupID,
    char ***pppszUsers,
    int *pnUserCount
    )
{
    uint32_t dwError = 0;
    if(!nGroupID || !pppszUsers || !pnUserCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_usermgmt_add_user_to_group(
    uint32_t nUserID,
    uint32_t nGroupID
    )
{
    uint32_t dwError = 0;
    if(!nUserID || !nGroupID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_usermgmt_remove_user_from_group(
    uint32_t nUserID,
    uint32_t nGroupID
    )
{
    uint32_t dwError = 0;
    if(!nUserID || !nGroupID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}
