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
        "/v1/prime/version",
        {demo_rest_version_json, NULL, NULL, NULL}
    },
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
demo_open_privsep_rest(
    PREST_AUTH pRestAuth,
    PPMDHANDLE *phPMD
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    char *pszUser = NULL;
    char *pszPass = NULL;

    if(!pRestAuth || !phPMD)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pRestAuth->nAuthMethod != REST_AUTH_BASIC)
    {
        dwError = ERROR_INVALID_REST_AUTH;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = base64_get_user_pass(
                  pRestAuth->pszAuthBase64,
                  &pszUser,
                  &pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rpc_open_privsep(
                  DEMO_PRIVSEP,
                  pszUser,
                  pszPass,
                  NULL,
                  &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    *phPMD = hPMD;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    return dwError;

error:
    rpc_free_handle(hPMD);
    goto cleanup;
}

uint32_t
demo_rest_version_json(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszVersion = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = demo_version(hPMD, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszOutputJson,
                                      "{\"version\":\"%s\"}",
                                      pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;
cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    rpc_free_handle(hPMD);
    return dwError;
error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
demo_rest_isprime_json(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    int nIsPrime = 0;
    int nPrimeToCheck = 0;
    char *pszOutputJson = NULL;
    const char *pszPrime = NULL;
    json_t *pJsonRoot = NULL;
    json_t *pJsonNum = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    const char *pszInputJson = pArgs->pszInputJson;

    if(!pArgs || IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

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

    dwError = demo_isprime(hPMD, nPrimeToCheck, &nIsPrime);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszOutputJson,
                                      "{\"isprime\":\"%s\"}",
                                      nIsPrime ? "yes" : "no");
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    rpc_free_handle(hPMD);
    return dwError;
error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
demo_rest_primes_json(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
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
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;
    const char *pszInputJson = pArgs->pszInputJson;

    if(!pArgs || IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = demo_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

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

    dwError = demo_primes(hPMD, nStart, nCount, &pnPrimes, &nPrimeCount);
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

    dwError = PMDAllocateStringPrintf(
                  &pszOutputJson,
                  "{\"primes\":[%s]}",
                  pszPrimes);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszPrimes);
    rpc_free_handle(hPMD);
    return dwError;
error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
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
