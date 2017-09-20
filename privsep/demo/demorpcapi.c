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
demo_privsep_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;
    wstring_t pwszVersion = NULL;

    rpc_authz_cred_handle_t hPriv = { 0 };
    unsigned char *authPrinc = NULL;
    unsigned32 group0member = 1;
    unsigned32 dwProtectLevel = 0;
    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    rpc_binding_inq_auth_caller(
        hBinding,
        &hPriv,
        &authPrinc,
        &dwProtectLevel,
        NULL, /* unsigned32 *authn_svc, */
        NULL, /* unsigned32 *authz_svc, */
        &dwError);
    if(dwError == 382312464)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_version(&pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    if(IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pwszVersion);
    goto cleanup;
}

unsigned32
demo_privsep_rpc_isprime(
    handle_t hBinding,
    int nPrime,
    int *pnIsPrime
    )
{
    uint32_t dwError = 0;
    int nIsPrime = 0;

    if(!hBinding || nPrime <= 0 || !pnIsPrime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_isprime(nPrime, &nIsPrime);
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

unsigned32
demo_privsep_rpc_primes(
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

    if(!hBinding || nStart <= 0 || nCount <= 0 || !ppInts)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_primes(nStart, nCount, &pnInts, &nPrimeCount);
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
