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
#include "pmd_rolemgmt_types.h"
#include "roleplugin.h"

uint32_t
rolemgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

uint32_t
rolemgmt_get_roles(
    PPMDHANDLE hHandle,
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

uint32_t
rolemgmt_get_role_version(
    PPMDHANDLE hHandle,
    const char *pszName,
    char **ppszVersion
    );

uint32_t
rolemgmt_get_prereqs(
    PPMDHANDLE hHandle,
    const char *pszName,
    PMD_ROLE_OPERATION nOperation,
    PPMD_ROLE_PREREQ *ppPrereqs,
    uint32_t *pdwPrereqCount
    );

uint32_t
rolemgmt_alter_with_config_json(
    PPMDHANDLE hHandle,
    const char *pszName,
    int nOperation,
    const char *pszConfigJson,
    char **ppszTaskUUID
    );

uint32_t
rolemgmt_get_status(
    PPMDHANDLE hHandle,
    const char *pszName,
    const char *pszTaskUUID,
    PMD_ROLE_STATUS *pnStatus
    );

uint32_t
rolemgmt_get_log(
    PPMDHANDLE hHandle,
    const char *pszTaskUUID,
    uint32_t dwOffset,
    uint32_t dwEntriesToFetch,
    PPMD_ROLEMGMT_TASK_LOG *ppTaskLogs,
    uint32_t *pdwTaskLogCount
    );

void
rolemgmt_free_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    );

#ifdef __cplusplus
}
#endif
