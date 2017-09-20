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
demo_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    wstring_t pwszVersion = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rpc_open_privsep_internal(DEMO_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_version(hPMD, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    rpc_free_handle(hPMD);
    return dwError;
error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMDRpcServerFreeMemory(pwszVersion);
    goto cleanup;
}

unsigned32
demo_rpc_isprime(
    handle_t hBinding,
    int nPrime,
    int *pnIsPrime
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || nPrime <= 0 || !pnIsPrime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rpc_open_privsep_internal(DEMO_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_isprime(hPMD, nPrime, pnIsPrime);
    BAIL_ON_PMD_ERROR(dwError);

error:
    rpc_free_handle(hPMD);
    return dwError;
}

unsigned32
demo_rpc_primes(
    handle_t hBinding,
    int nStart,
    int nCount,
    PINT_ARRAY *ppInts
    )
{
    uint32_t dwError = 0;
    int *pnInts = NULL;
    int nPrimeCount = 0;
    PINT_ARRAY pIntArray = NULL;
    int *pnIntsSource = NULL;
    int *pnIntsDest = NULL;
    int i = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || nStart <= 0 || nCount <= 0 || !ppInts)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rpc_open_privsep_internal(DEMO_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_primes(hPMD, nStart, nCount, &pnInts, &nPrimeCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(PINT_ARRAY),
                                         (void **)&pIntArray);
    BAIL_ON_PMD_ERROR(dwError);

    pIntArray->dwCount = nPrimeCount;
    dwError = PMDRpcServerAllocateMemory(sizeof(int) * nPrimeCount,
                                         (void **)&pIntArray->pnInts);
    BAIL_ON_PMD_ERROR(dwError);

    pnIntsSource = pnInts;
    pnIntsDest = pIntArray->pnInts;
    for(i = 0; i < nPrimeCount; ++i, ++pnIntsSource, ++pnIntsDest)
    {
        *pnIntsDest = *pnIntsSource;
    }

    *ppInts = pIntArray;
cleanup:
    PMD_SAFE_FREE_MEMORY(pnInts);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppInts)
    {
        *ppInts = NULL;
    }
    if(pIntArray)
    {
        PMDRpcServerFreeMemory(pIntArray->pnInts);
        PMDRpcServerFreeMemory(pIntArray);
    }
    goto cleanup;
}
