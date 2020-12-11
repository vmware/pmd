/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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
rolemgmt_free_role(
    PPMD_ROLEMGMT_ROLE pRole
    );

uint32_t
rolemgmt_status_from_string(
    const char *pszStatus,
    PMD_ROLE_STATUS *pnStatus
    )
{
    uint32_t dwError = 0;
    size_t nSize = 0;
    size_t i = 0;
    PMD_ROLE_STATUS nStatus = ROLE_STATUS_NONE;
    struct stLookup
    {
        PMD_ROLE_STATUS nStatus;
        const char *pszStatus;
    }arLookup[] =
    {
        {ROLE_STATUS_SUCCESS,     "success"},
        {ROLE_STATUS_FAILURE,     "failure"},
        {ROLE_STATUS_NOT_STARTED, "not started"},
        {ROLE_STATUS_IN_PROGRESS, "in progress"}
    };
    nSize = sizeof(arLookup)/sizeof(arLookup[0]);

    if(!pszStatus || !pnStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < nSize; ++i)
    {
        if(!strcmp(pszStatus, arLookup[i].pszStatus))
        {
            nStatus = arLookup[i].nStatus;
            break;
        }
    }

    if(nStatus == ROLE_STATUS_NONE)
    {
        dwError = ERROR_PMD_ROLE_BAD_STATUS;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pnStatus= nStatus;

cleanup:
    return dwError;

error:
    if(pnStatus)
    {
        *pnStatus = ROLE_STATUS_NONE;
    }
    goto cleanup;
}

uint32_t
rolemgmt_status_to_string(
    PMD_ROLE_STATUS nStatus,
    char **ppszStatus
    )
{
    uint32_t dwError = 0;
    char *pszStatus = NULL;
    size_t nSize = 0;
    char *pszStrings[] =
    {
        "none",
        "success",
        "failure",
        "not started",
        "in progress"
    };
    nSize = sizeof(pszStrings)/sizeof(pszStrings[0]);

    if(nStatus <= ROLE_STATUS_NONE ||
       nStatus > nSize ||
       !ppszStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszStrings[nStatus], &pszStatus);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszStatus = pszStatus;

cleanup:
    return dwError;

error:
    if(ppszStatus)
    {
        *ppszStatus = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszStatus);
    goto cleanup;
}


void
rolemgmt_free_children(
    PPMD_ROLEMGMT_ROLE pRole
    )
{
    int i = 0;
    for(i = 0; i < pRole->nChildCount; ++i)
    {
        rolemgmt_free_role(pRole->ppChildren[i]);
    }
    PMD_SAFE_FREE_MEMORY(pRole->ppChildren);
}

void
rolemgmt_free_role(
    PPMD_ROLEMGMT_ROLE pRole
    )
{
    int i = 0;
    if(!pRole)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pRole->pszName);
    PMD_SAFE_FREE_MEMORY(pRole->pszParent);
    PMD_SAFE_FREE_MEMORY(pRole->pszDisplayName);
    PMD_SAFE_FREE_MEMORY(pRole->pszDescription);
    PMD_SAFE_FREE_MEMORY(pRole->pszPlugin);
    rolemgmt_free_children(pRole);
    PMDFreeMemory(pRole);
}

void
rolemgmt_free_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    )
{
    if(!pRoles)
    {
        return;
    }
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    while(pRoles)
    {
        pRole = pRoles->pNext;
        rolemgmt_free_role(pRoles);
        pRoles = pRole;
    }
}
