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
demo_client_version(
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

    DO_RPC(demo_rpc_version(hHandle->hRpc, &pwszVersion), dwError);
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
    goto cleanup;
}

uint32_t
demo_client_isprime(
    PPMDHANDLE hHandle,
    int nNumToCheck,
    int *pnIsPrime
    )
{
    uint32_t dwError = 0;
    int nIsPrime = 0;

    if(!hHandle || nNumToCheck <= 0 || !pnIsPrime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(demo_rpc_isprime(hHandle->hRpc, nNumToCheck, &nIsPrime), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    *pnIsPrime = nIsPrime;

cleanup:
    return dwError;

error:
    if(pnIsPrime)
    {
        *pnIsPrime = 0;
    }
    goto cleanup;
}

uint32_t
demo_client_primes(
    PPMDHANDLE hHandle,
    int nStart,
    int nCount,
    int **ppnPrimes,
    int *pnPrimesCount
    )
{
    uint32_t dwError = 0;
    int i = 0;
    int *pnPrimes = NULL;
    int nPrimeCount = 0;
    PINT_ARRAY pIntArray = NULL;
    int *pnDest = NULL;
    int *pnSource = NULL;

    if(!hHandle || nStart <= 0 || nCount <= 0 || !ppnPrimes || !pnPrimesCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(demo_rpc_primes(hHandle->hRpc, nStart, nCount, &pIntArray),
           dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pIntArray)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nPrimeCount = pIntArray->dwCount;

    dwError = PMDAllocateMemory(sizeof(int) * (nPrimeCount + 1),
                                (void **)&pnPrimes);
    BAIL_ON_PMD_ERROR(dwError);

    pnSource = pIntArray->pnInts;
    pnDest = pnPrimes;
    for(i = 0; i < nPrimeCount; ++i, ++pnSource, ++pnDest)
    {
        *pnDest = *pnSource;
    }

    *ppnPrimes = pnPrimes;
    *pnPrimesCount = nPrimeCount;

cleanup:
    if(pIntArray)
    {
        if(pIntArray->pnInts)
        {
            PMDRpcClientFreeMemory(pIntArray->pnInts);
        }
        PMDRpcClientFreeMemory(pIntArray);
    }
    return dwError;

error:
    if(ppnPrimes)
    {
        *ppnPrimes = NULL;
    }
    if(pnPrimesCount)
    {
        *pnPrimesCount = 0;
    }
    PMDFreeMemory(pnPrimes);
    goto cleanup;
}
