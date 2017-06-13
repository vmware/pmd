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
PMDRpcServerAllocateMemory(
    size_t size,
    void** ppMemory
    )
{
    uint32_t dwError = 0;
    void* pMemory = NULL;

    if (size <= 0 || !ppMemory)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pMemory = rpc_ss_allocate(size);
    if (!pMemory)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    memset(pMemory,0, size);

    *ppMemory = pMemory;

cleanup:

    return dwError;

error:

    if (ppMemory)
    {
        *ppMemory = NULL;
    }
    PMDRpcServerFreeMemory(pMemory);

    goto cleanup;
}

uint32_t
PMDRpcServerAllocateStringA(
    const char* pszSource,
    char** ppszTarget
    )
{
    uint32_t dwError = 0;
    PSTR pszTarget = NULL;
    size_t length = 0;

    if (!pszSource)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    length = strlen(pszSource);

    dwError = PMDRpcServerAllocateMemory(length + 1, (void**)&pszTarget);
    BAIL_ON_PMD_ERROR(dwError);

    memcpy(pszTarget, pszSource, length);

    pszTarget[length] = '\0';

    *ppszTarget = pszTarget;

cleanup:

    return dwError;

error:

    *ppszTarget = NULL;

    if (pszTarget)
    {
        PMDRpcServerFreeMemory(pszTarget);
    }

    goto cleanup;
}

uint32_t
PMDRpcServerAllocateStringW(
    wstring_t pwszSource,
    wstring_t* ppwszTarget
    )
{
    uint32_t  dwError = 0;
    size_t len = 0;
    PWSTR  pwszTarget = NULL;

    if (!pwszSource || !ppwszTarget)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDGetStringLengthW(pwszSource, &len);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(
                    sizeof(WCHAR) * (len + 1),
                    (PVOID*)&pwszTarget);
    BAIL_ON_PMD_ERROR(dwError);

    memcpy((PBYTE)pwszTarget, (PBYTE)pwszSource, sizeof(WCHAR) * len);

    *ppwszTarget = pwszTarget;

cleanup:

    return dwError;

error:

    if (ppwszTarget)
    {
        *ppwszTarget = NULL;
    }

    if (pwszTarget)
    {
        PMDRpcServerFreeMemory(pwszTarget);
    }

    goto cleanup;
}

uint32_t
PMDRpcServerAllocateWFromA(
    const char* pszSource,
    wstring_t* ppwszDest
    )
{
    uint32_t dwError = 0;
    wstring_t pwszTemp = NULL;
    wstring_t pwszDest = NULL;

    if(pszSource)
    {
        dwError = PMDAllocateStringWFromA(pszSource, &pwszTemp);
        if(dwError == -1)
        {
           dwError = PMDAllocateStringWFromA("", &pwszTemp);
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDRpcServerAllocateStringW(pwszTemp, &pwszDest);
        BAIL_ON_PMD_ERROR(dwError);
    }
    *ppwszDest = pwszDest;
cleanup:
    PMD_SAFE_FREE_MEMORY(pwszTemp);
    return dwError;
error:
    if(ppwszDest)
    {
        *ppwszDest = NULL;
    }
    if(pwszDest)
        PMDRpcServerFreeMemory(pwszDest);
    goto cleanup;
}

void
PMDRpcServerFreeMemory(
    void* pMemory
    )
{
    if (pMemory)
    {
        rpc_ss_free(pMemory);
    }
}
