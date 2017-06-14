/*
 * Copyright 2017 VMware, Inc. All rights reserved.
 * This software is released under the BSD 2-Clause license.
 * The full license information can be found in the LICENSE
 * in the root directory of this project.
 * SPDX-License-Identifier: BSD-2
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
