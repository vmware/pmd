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
demo_version(
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

    dwError = PMDAllocateString(DEMO_VERSION, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;
cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(ppszVersion);
    goto cleanup;
}

uint32_t
demo_isprime(
    int nNumToCheck,
    int *pnIsPrime
    )
{
    uint32_t dwError = 0;
    int nIsPrime = 1;
    int nLimit = 0;
    int nIndex = 0;

    if(nNumToCheck <= 0 || !pnIsPrime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(nNumToCheck == 1)
    {
        *pnIsPrime = 0;
        goto cleanup;
    }

    if(nNumToCheck < 4)
    {
        *pnIsPrime = 1;
        goto cleanup;
    }

    if(nNumToCheck % 2 == 0)
    {
        *pnIsPrime = 0;
        goto cleanup;
    }

    nLimit = sqrt(nNumToCheck);
    for(nIndex = 3; nIndex <= nLimit; nIndex+=2)
    {
        if(nNumToCheck % nIndex == 0)
        {
            //fprintf(stdout, "%d is divisible by %d\n", nNumber, nIndex);
            nIsPrime = 0;
            break;
        }
    }

    *pnIsPrime = nIsPrime;

cleanup:
    return dwError;
error:
    goto cleanup; 
}

uint32_t
demo_primes(
    int nStart,
    int nCount,
    int **ppnPrimes,
    int *pnPrimeCount
    )
{
    uint32_t dwError = 0;
    int nIsPrime = 0;
    int nMaxPrimesInRange = (nCount/2) + 1;
    int *pnPrimes = NULL;
    int nPrimeCount = 0;

    if(nStart <= 0 || nCount == 0 || !ppnPrimes)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(int) * nMaxPrimesInRange,
                                (void **)&pnPrimes);
    BAIL_ON_PMD_ERROR(dwError);

    do
    {
        dwError = demo_isprime(nStart, &nIsPrime);
        BAIL_ON_PMD_ERROR(dwError);

        if(nIsPrime)
        {
            pnPrimes[nPrimeCount++] = nStart;
        }
        ++nStart;
    }while(--nCount);

    *ppnPrimes = pnPrimes;
    *pnPrimeCount = nPrimeCount;

cleanup:
    return dwError;
error:
    if(ppnPrimes)
    {
        *ppnPrimes = NULL;
    }
    if(pnPrimeCount)
    {
        *pnPrimeCount = 0;
    }
    PMD_SAFE_FREE_MEMORY(pnPrimes);
    goto cleanup; 
}

