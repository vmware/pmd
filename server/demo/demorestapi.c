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

REST_MODULE _demo_rest_module[] = 
{
    {
        "/v1/prime/isprime",
        {demo_rest_isprime_json, NULL, NULL, NULL}
    },
    {
        "/v1/prime/primes",
        {demo_rest_primes_json, NULL, NULL, NULL}
    },
    {
        "/v1/prime/fav",
        {
            demo_rest_get_fav_json,
            demo_rest_set_fav_json,
            demo_rest_update_fav_json,
            demo_rest_delete_fav_json
        }
    },
    {0}
};

uint32_t
demo_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _demo_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
demo_rest_isprime_json(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    int nIsPrime = 0;
    int nPrimeToCheck = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    const char *pszPrime = NULL;
    json_t *pJsonRoot = NULL;
    json_t *pJsonNum = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJsonRoot);
    BAIL_ON_PMD_ERROR(dwError);

    pJsonNum = json_object_get(pJsonRoot, "num");
    if(!pJsonNum)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pszPrime = json_string_value(pJsonNum);
    if(IsNullOrEmptyString(pszPrime))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nPrimeToCheck = atoi(pszPrime);

    dwError = demo_isprime(nPrimeToCheck, &nIsPrime);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszOutputJson,
                                      "{\"isprime\":\"%s\"}",
                                      nIsPrime ? "yes" : "no");
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    return dwError;
error:
    goto cleanup; 
}

uint32_t
demo_rest_primes_json(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    int nCount = 0;
    int nStart = 0;
    int *pnPrimes = NULL;
    int nPrimeCount = 0;
    const char *pszStart = NULL;
    const char *pszCount = NULL;
    json_t *pJsonRoot = NULL;
    json_t *pJsonStart = NULL;
    json_t *pJsonCount = NULL;
    char *pszOutputJson = NULL;
    char *pszPrimes = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJsonRoot);
    BAIL_ON_PMD_ERROR(dwError);

    pJsonStart = json_object_get(pJsonRoot, "start");
    if(!pJsonStart)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pszStart = json_string_value(pJsonStart);
    if(IsNullOrEmptyString(pszStart))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    nStart= atoi(pszStart);

    pJsonCount = json_object_get(pJsonRoot, "count");
    if(!pJsonCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pszCount = json_string_value(pJsonCount);
    if(IsNullOrEmptyString(pszCount))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    nCount = atoi(pszCount);

    dwError = demo_primes(nStart, nCount, &pnPrimes, &nPrimeCount);
    BAIL_ON_PMD_ERROR(dwError);

    if(pnPrimes && nPrimeCount > 0)
    {
        int nIndex = 0;
        int nOffset = 0;
        char pszEnd[20];

        sprintf(pszEnd, "%d", nStart + nCount);
        dwError = PMDAllocateMemory(((strlen(pszEnd) + 1) * (nPrimeCount * 2)),
                                    (void **)&pszPrimes);
        BAIL_ON_PMD_ERROR(dwError);

        do
        {
            if(nIndex > 0)
            {
                sprintf(pszPrimes + nOffset, ",");
                nOffset++;
            }
            sprintf(pszPrimes + nOffset, "%d", pnPrimes[nIndex]);
            nIndex++;
            nOffset = strlen(pszPrimes);
        }while(--nPrimeCount);
    }

    dwError = PMDAllocateStringPrintf(&pszOutputJson, "{\"primes\":[%s]}", pszPrimes);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszPrimes);
    return dwError;
error:
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup; 
}

uint32_t
demo_rest_get_fav_json(
    void *pInputJson,
    void **ppOutputJson
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
demo_rest_set_fav_json(
    void *pInputJson,
    void **ppOutputJson
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
demo_rest_delete_fav_json(
    void *pInputJson,
    void **ppOutputJson
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
demo_rest_update_fav_json(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup; 
}
