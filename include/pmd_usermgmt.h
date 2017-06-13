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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "pmdtypes.h"
#include "pmd_usermgmt_types.h"

uint32_t
usermgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

uint32_t
usermgmt_add_user(
    PPMDHANDLE hHandle,
    const char *pszName
    );

uint32_t
usermgmt_delete_user(
    PPMDHANDLE hHandle,
    const char *pszName
    );

uint32_t
usermgmt_add_group(
    PPMDHANDLE hHandle,
    const char *pszName
    );

uint32_t
usermgmt_delete_group(
    PPMDHANDLE hHandle,
    const char *pszName
    );

uint32_t
usermgmt_get_userid(
    PPMDHANDLE hHandle,
    const char *pszName,
    uint32_t *pnUID
    );

uint32_t
usermgmt_get_groupid(
    PPMDHANDLE hHandle,
    const char *pszName,
    uint32_t *pnGID
    );

uint32_t
usermgmt_get_users(
    PPMDHANDLE hHandle,
    PPMD_USER *ppUsers
    );

uint32_t
usermgmt_get_groups(
    PPMDHANDLE hHandle,
    PPMD_GROUP *ppGroups
    );

uint32_t
usermgmt_get_groups_for_user(
    PPMDHANDLE hHandle,
    uint32_t nUserID,
    char ***pppszGroups,
    int *pnGroupCount      
    );
    
uint32_t
usermgmt_get_users_for_group(
    PPMDHANDLE hHandle,
    uint32_t nGroupID,
    char ***pppszUsers,
    int *pnUserCount
    );

uint32_t
usermgmt_add_user_to_group(
    PPMDHANDLE hHandle,
    uint32_t nUserID,
    uint32_t nGroupID
    );

uint32_t
usermgmt_remove_user_from_group(
    PPMDHANDLE hHandle,
    uint32_t nUserID,
    uint32_t nGroupID
    );

void
usermgmt_free_user(
    PPMD_USER pUser
    );

void
usermgmt_free_group(
    PPMD_GROUP pGroup
    );

#ifdef __cplusplus
}
#endif
