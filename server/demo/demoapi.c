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
demo_open_privsep(
    PPMDHANDLE *phPMD
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    wstring_t pwszVersion = NULL;

    if(!phPMD)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rpc_open_privsep(
        DEMO_PRIVSEP,
        &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    *phPMD = hPMD;

cleanup:
    return dwError;

error:
    rpc_free_handle(hPMD);
    goto cleanup;
}

uint32_t
demo_version(
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_open_privsep(&hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_client_version(hPMD, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;
cleanup:
    rpc_free_handle(hPMD);
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
    int nNumToCheck,
    int *pnIsPrime
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!pnIsPrime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_open_privsep(&hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_client_isprime(hPMD, nNumToCheck, pnIsPrime);
    BAIL_ON_PMD_ERROR(dwError);

error:
    rpc_free_handle(hPMD);
    return dwError;
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
    PPMDHANDLE hPMD = NULL;

    if(nStart <= 0 || nCount == 0 || !ppnPrimes || !pnPrimeCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_open_privsep(&hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_client_primes(
                  hPMD,
                  nStart,
                  nCount,
                  ppnPrimes,
                  pnPrimeCount);
    BAIL_ON_PMD_ERROR(dwError);

error:
    rpc_free_handle(hPMD);
    return dwError;
}

uint32_t
demo_get_fav(
    int *ppnPrimes,
    int *pnCount
    )
{
    uint32_t dwError = 0;
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup; 
}

uint32_t
demo_set_fav(
    int *pnPrimes,
    int nCount
    )
{
    uint32_t dwError = 0;
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup; 
}

uint32_t
demo_delete_fav(
    int nPrimeToDelete
    )
{
    uint32_t dwError = 0;
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup; 
}

uint32_t
demo_update_fav(
    int nPrimeOld,
    int nPrimeNew
    )
{
    uint32_t dwError = 0;
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup; 
}
