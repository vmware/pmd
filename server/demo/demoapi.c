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
    PPMDHANDLE hPMD,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(hPMD && !ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_client_version(hPMD, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;
cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszVersion);
    goto cleanup;
}

uint32_t
demo_isprime(
    PPMDHANDLE hPMD,
    int nNumToCheck,
    int *pnIsPrime
    )
{
    uint32_t dwError = 0;

    if(!hPMD || !pnIsPrime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_client_isprime(hPMD, nNumToCheck, pnIsPrime);
    BAIL_ON_PMD_ERROR(dwError);

error:
    return dwError;
}

uint32_t
demo_primes(
    PPMDHANDLE hPMD,
    int nStart,
    int nCount,
    int **ppnPrimes,
    int *pnPrimeCount
    )
{
    uint32_t dwError = 0;

    if(!hPMD || nStart <= 0 || nCount == 0 || !ppnPrimes || !pnPrimeCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_client_primes(
                  hPMD,
                  nStart,
                  nCount,
                  ppnPrimes,
                  pnPrimeCount);
    BAIL_ON_PMD_ERROR(dwError);

error:
    return dwError;
}
