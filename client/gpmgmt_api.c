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
gpmgmt_get_version(
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

    DO_RPC(gpmgmt_rpc_version(hHandle->hRpc, &pwszVersion), dwError);
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
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszVersion);
    goto cleanup;
}