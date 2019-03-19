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
pmd_rolemgmt_plugin_get_version(
    const PPMD_PLUGIN_MODULE pModule,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!pModule || !ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pModule->nDisabled)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_DISABLED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pModule->pInterface || !pModule->pInterface->pFnRoleVersion)
    {
        dwError = ERROR_PMD_ROLE_UNMAPPED_FN;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pModule->pInterface->pFnRoleVersion(&pszVersion);
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
pmd_rolemgmt_plugin_open(
    const PPMD_PLUGIN_MODULE pModule,
    PPMD_ROLE_HANDLE *ppRoleHandle
    )
{
    uint32_t dwError = 0;
    PPMD_ROLE_HANDLE pRoleHandle = NULL;
    if(!pModule || !ppRoleHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pModule->nDisabled)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_DISABLED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pModule->pInterface || !pModule->pInterface->pFnRoleOpen)
    {
        dwError = ERROR_PMD_ROLE_UNMAPPED_FN;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pModule->pInterface->pFnRoleOpen(&pRoleHandle);
    BAIL_ON_PMD_ERROR(dwError);

    *ppRoleHandle = pRoleHandle;

cleanup:
    return dwError;

error:
    if(ppRoleHandle)
    {
        *ppRoleHandle = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_plugin_close(
    const PPMD_PLUGIN_MODULE pModule,
    PPMD_ROLE_HANDLE pRoleHandle
    )
{
    uint32_t dwError = 0;
    if(!pModule || !pRoleHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pModule->pInterface || !pModule->pInterface->pFnRoleClose)
    {
        dwError = ERROR_PMD_ROLE_UNMAPPED_FN;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pModule->pInterface->pFnRoleClose(pRoleHandle);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_rolemgmt_plugin_get_prereqs(
    const PPMD_PLUGIN_MODULE pModule,
    PMD_ROLE_OPERATION nOperation,
    const PPMD_ROLE_HANDLE pRoleHandle,
    PPMD_ROLE_PREREQ *ppPreReqs,
    uint32_t *pdwPreReqCount
    )
{
    uint32_t dwError = 0;
    PPMD_ROLE_PREREQ pPreReqs = NULL;
    uint32_t dwPreReqCount = 0;

    if(!pModule || !pRoleHandle || !ppPreReqs || !pdwPreReqCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pModule->nDisabled)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_DISABLED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pModule->pInterface || !pModule->pInterface->pFnRoleGetPreReqs)
    {
        dwError = ERROR_PMD_ROLE_UNMAPPED_FN;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pModule->pInterface->pFnRoleGetPreReqs(
                  pRoleHandle,
                  nOperation,
                  &pPreReqs,
                  &dwPreReqCount);
    BAIL_ON_PMD_ERROR(dwError);

    *ppPreReqs = pPreReqs;
    *pdwPreReqCount = dwPreReqCount;

cleanup:
    return dwError;

error:
    if(ppPreReqs)
    {
        *ppPreReqs = NULL;
    }
    if(pdwPreReqCount)
    {
        *pdwPreReqCount = 0;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_plugin_alter(
    const PPMD_PLUGIN_MODULE pModule,
    const PPMD_PLUGIN_TASK pTask
    )
{
    uint32_t dwError = 0;

    if(!pModule || !pTask)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pModule->nDisabled)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_DISABLED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pModule->pInterface || !pModule->pInterface->pFnRoleAlter)
    {
        dwError = ERROR_PMD_ROLE_UNMAPPED_FN;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pModule->pInterface->pFnRoleAlter(
                  pTask->pRoleHandle,
                  pTask->nOperation,
                  pTask->pszConfigJson,
                  pTask->pszTaskUUID,
                  pTask->pFnProgressCallback,
                  NULL
                  );
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}
