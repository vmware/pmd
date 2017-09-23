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

PREST_API_DEF gpApiDef = NULL;
static const char *gpszPubKeyFile = NULL;

uint32_t
rest_register_api_spec(
    PVMREST_HANDLE pRestHandle,
    PREST_API_DEF pApiDef,
    int nUseKerberos,
    PREST_PROCESSOR *ppRestProcessor
    )
{
    uint32_t dwError = 0;
    PREST_API_MODULE pModule = NULL;
    PREST_PROCESSOR pRestProcessor = NULL;

    if(!pRestHandle || !pApiDef || !ppRestProcessor)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(REST_PROCESSOR),
                                (void **)&pRestProcessor);
    BAIL_ON_PMD_ERROR(dwError);

    pRestProcessor->pfnHandleCreate = &rest_method;
    pRestProcessor->pfnHandleRead = &rest_method;
    pRestProcessor->pfnHandleUpdate = &rest_method;
    pRestProcessor->pfnHandleDelete = &rest_method;
    pRestProcessor->pfnHandleOthers = &handle_options;

    for(pModule = pApiDef->pModules; pModule; pModule = pModule->pNext)
    {
        PREST_API_ENDPOINT pEndPoint = pModule->pEndPoints;
        for(; pEndPoint; pEndPoint = pEndPoint->pNext)
        {
            dwError = VmRESTRegisterHandler(
                          pRestHandle,
                          pEndPoint->pszName,
                          pRestProcessor,
                          NULL);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppRestProcessor = pRestProcessor;
    gpApiDef = pApiDef;
    gnUseKerberos = nUseKerberos;

cleanup:
    return dwError;

error:
    if(ppRestProcessor)
    {
        *ppRestProcessor = NULL;
    }
    goto cleanup;
}

uint32_t
rest_set_privsep_pubkey(
    const char *pszPubKeyFile
    )
{
    uint32_t dwError = 0;
    if(IsNullOrEmptyString(pszPubKeyFile))
    {
        dwError = ERROR_PMD_MISSING_PRIVSEP_PUBKEY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpszPubKeyFile = pszPubKeyFile;

error:
    return dwError;
}

uint32_t
find_key(
    const char *pszKey,
    PKEYVALUE pKeyValues,
    PKEYVALUE *ppKeyValue
    )
{
    uint32_t dwError = 0;
    PKEYVALUE pKeyValue = NULL;

    if(!pszKey || !pKeyValues || !ppKeyValue)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(; pKeyValues; pKeyValues = pKeyValues->pNext)
    {
        if(!strcmp(pszKey, pKeyValues->pszKey))
        {
            pKeyValue = pKeyValues;
            break;
        }
    }

    if(!pKeyValue)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppKeyValue = pKeyValue;

cleanup:
    return dwError;

error:
    if(ppKeyValue)
    {
        *ppKeyValue = NULL;
    }
    goto cleanup;
}

uint32_t
rest_validate_keyvalues(
    PREST_API_METHOD pMethod,
    PKEYVALUE pKeyValues,
    uint32_t nSuppliedParamsCount
    )
{
    uint32_t dwError = 0;
    PREST_API_PARAM *ppRequiredParams = NULL;
    PREST_API_PARAM *ppRequiredParamsTemp = NULL;
    int nRequiredParamsCount = 0;

    if(!pMethod)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pMethod->pParams)
    {
        if(nSuppliedParamsCount)
        {
            fprintf(stderr,
                    "%d parameter(s) supplied but none defined\n",
                    nSuppliedParamsCount);
        }
        goto cleanup;
    }

    dwError = coapi_get_required_params(pMethod,
                                          &ppRequiredParams,
                                          &nRequiredParamsCount);
    BAIL_ON_PMD_ERROR(dwError);

    if(nRequiredParamsCount > nSuppliedParamsCount)
    {
        fprintf(stderr,
                "method requires %d params. %d supplied\n",
                nRequiredParamsCount,
                nSuppliedParamsCount);
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(ppRequiredParamsTemp = ppRequiredParams;
        ppRequiredParamsTemp && *ppRequiredParamsTemp;
        ++ppRequiredParamsTemp)
    {
        int nValid = 0;
        PKEYVALUE pKeyValue = NULL;
        const char *pszName = (*ppRequiredParamsTemp)->pszName;

        dwError = find_key(pszName, pKeyValues, &pKeyValue);
        if(dwError == ENOENT)
        {
            fprintf(stderr,
                    "required param %s is not supplied\n",
                    pszName);
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = coapi_check_param(*ppRequiredParamsTemp,
                                      pKeyValue->pszValue,
                                      &nValid);
        if(dwError == EINVAL)
        {
            fprintf(stderr,
                    "Value %s for param %s is not valid\n",
                    pKeyValue->pszValue,
                    pszName);
        }
        BAIL_ON_PMD_ERROR(dwError);
    }
cleanup:
    PMD_SAFE_FREE_MEMORY(ppRequiredParams);
    return dwError;

error:
    goto cleanup;
}

uint32_t
rest_get_json_string(
    PREST_API_METHOD pMethod,
    PREST_REQUEST pRequest,
    uint32_t dwCount,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    PKEYVALUE pKeyValue = NULL;
    char *pszJson = NULL;

    dwError = rest_get_keyvalues(pRequest, dwCount, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    //should have a rest_validate_ when there are no params supplied
    //pKeyValue is null and dwCount is 0 at this time. this function
    //is written to tolerate this but it creates the unnatural check
    //for pKeyValue below.
    dwError = rest_validate_keyvalues(pMethod, pKeyValue, dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    if(pKeyValue)
    {
        dwError = get_json_string(pKeyValue, &pszJson);
        BAIL_ON_PMD_ERROR(dwError);
    }
    *ppszJson = pszJson;

cleanup:
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
rest_get_keyvalues(
    PREST_REQUEST pRequest,
    uint32_t dwCount,
    PKEYVALUE *ppKeyValue
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    PKEYVALUE pKeyValue = NULL;
    PKEYVALUE pKeyValueCur = NULL;
    char *pszKey = NULL;//do not free this
    char *pszValue = NULL;//do not free this

    for(dwIndex = dwCount; dwIndex >= 1; --dwIndex)
    {
        dwError = PMDAllocateMemory(sizeof(KEYVALUE),
                                    (void **)&pKeyValueCur);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = VmRESTGetParamsByIndex(
                      pRequest,
                      dwCount,
                      dwIndex,
                      &pszKey,
                      &pszValue
                      );
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pszKey, &pKeyValueCur->pszKey);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pszValue, &pKeyValueCur->pszValue);
        BAIL_ON_PMD_ERROR(dwError);

        pKeyValueCur->pNext = pKeyValue;
        pKeyValue = pKeyValueCur;
        pKeyValueCur = NULL;
    }

    *ppKeyValue = pKeyValue;

cleanup:
    return dwError;

error:
    if(ppKeyValue)
    {
        *ppKeyValue = NULL;
    }
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    if(pKeyValueCur)
    {
        free_keyvalue(pKeyValueCur);
    }
    goto cleanup;
}

uint32_t
find_in_module(
    PREST_REQUEST pRequest,
    PREST_MODULE pRestModule,
    const char *pszURI,
    PFN_MODULE_ENDPOINT_CB *ppfnHandler
    )
{
    uint32_t dwError = 0;
    char *pszMethod = NULL;
    PFN_MODULE_ENDPOINT_CB pfnHandler = NULL;

    if(!pRequest || !pRestModule || IsNullOrEmptyString(pszURI))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    while(pRestModule->pszEndPoint)
    {
        if(strcmp(pszURI, pRestModule->pszEndPoint) == 0)
        {
            RESTMETHOD nMethod = METHOD_INVALID;

            dwError = VmRESTGetHttpMethod(pRequest, &pszMethod);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = coapi_get_rest_method(pszMethod, &nMethod);
            BAIL_ON_PMD_ERROR(dwError);

            pfnHandler = pRestModule->pFnEndPointMethods[nMethod];

            break;
        }
        pRestModule++;
    }

    *ppfnHandler = pfnHandler;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszMethod);
    return dwError;

error:
    if(ppfnHandler)
    {
        *ppfnHandler = NULL;
    }
    goto cleanup;
}


uint32_t
get_uri_from_request(
    PREST_REQUEST pRequest,
    char **ppszURI
    )
{
    uint32_t dwError = 0;
    char *pszRealURI = NULL;
    char *pszURI = NULL;
    char *pszTempURI = NULL;

    dwError = VmRESTGetHttpURI(pRequest, &pszRealURI);
    BAIL_ON_PMD_ERROR(dwError);

    pszTempURI = strchr(pszRealURI, '?');
    if(pszTempURI)
    {
        *pszTempURI = '\0';
    }
    pszTempURI = pszRealURI;

    if(IsNullOrEmptyString(pszTempURI))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszTempURI, &pszURI);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszURI = pszURI;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszRealURI);
    return dwError;

error:
    if(ppszURI)
    {
        *ppszURI = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszURI);
    goto cleanup;
}

uint32_t
find_module_entry_spec(
    PREST_REQUEST pRequest,
    const char *pszURI,
    PREST_API_METHOD *ppMethod
    )
{
    uint32_t dwError = 0;
    PREST_API_METHOD pMethod = NULL;
    char *pszMethod = NULL;

    if(!pRequest || IsNullOrEmptyString(pszURI) || !ppMethod)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = VmRESTGetHttpMethod(pRequest, &pszMethod);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = coapi_find_handler(gpApiDef,
                                   pszURI,
                                   pszMethod,
                                   &pMethod);
    BAIL_ON_PMD_ERROR(dwError);

    *ppMethod = pMethod;

cleanup:
    return dwError;

error:
    if(ppMethod)
    {
        *ppMethod = NULL;
    }
    goto cleanup;
}

uint32_t
rest_method(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse,
    uint32_t paramsCount
    )
{
    uint32_t dwError = 0;
    uint32_t done = 0;
    char *pszJsonIn = NULL;
    char *pszJsonOut = NULL;
    char pszDataLen[10] = {0};
    PFN_MODULE_ENDPOINT_CB pfnHandler = NULL;
    PREST_API_METHOD pMethod = NULL;
    int nDataLength = 0;
    char *pszURI = NULL;
    REST_FN_ARGS stArgs = {0};
    REST_AUTH_ARGS stAuthArgs =
    {
        pRestHandle,
        pRequest,
        ppResponse
    };

    dwError = get_uri_from_request(pRequest, &pszURI);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = find_module_entry_spec(pRequest, pszURI, &pMethod);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rest_get_json_string(pMethod, pRequest, paramsCount, &pszJsonIn);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pre_process_auth(&stAuthArgs, &stAuthArgs.pRestAuth);
    BAIL_ON_PMD_ERROR(dwError);

    stArgs.pAuthArgs = &stAuthArgs;
    stArgs.pszInputJson = pszJsonIn;

    dwError = pMethod->pFnImpl(&stArgs, (void **)&pszJsonOut);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetSuccessResponse(pRequest, ppResponse);
    BAIL_ON_PMD_ERROR(dwError);

    nDataLength = strlen(pszJsonOut);
    sprintf(pszDataLen, "%d", nDataLength);
    if(nDataLength < MAX_HTTP_DATA_LEN)
    {
        dwError = VmRESTSetDataLength(ppResponse, pszDataLen);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = VmRESTSetData(
                      pRestHandle,
                      ppResponse,
                      pszJsonOut,
                      nDataLength,
                      &done
                      );
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        int nChunkLength = 0;
        int nLengthSent = 0;
        unsigned int nBytesWritten = 0;
        dwError = VmRESTSetDataLength(ppResponse, NULL);
        BAIL_ON_PMD_ERROR(dwError);

        do
        {
            nChunkLength = nDataLength > MAX_HTTP_DATA_LEN ?
                                         MAX_HTTP_DATA_LEN : nDataLength;
            dwError = VmRESTSetData(
                            pRestHandle,
                            ppResponse,
                            pszJsonOut + nLengthSent,
                            nChunkLength,
                            &nBytesWritten
                               );
            if (dwError != REST_ENGINE_MORE_IO_REQUIRED)
            {
                BAIL_ON_PMD_ERROR(dwError);
            }
            nLengthSent += nBytesWritten;
            nDataLength -= nBytesWritten;
            nBytesWritten = 0; //reset the value
            usleep(1000);
        }while(dwError == REST_ENGINE_MORE_IO_REQUIRED);
    }
cleanup:
    PMD_SAFE_FREE_MEMORY(pszURI);
    PMD_SAFE_FREE_MEMORY(pszJsonIn);
    PMD_SAFE_FREE_MEMORY(pszJsonOut);
    return dwError;

error:
    goto cleanup;
}

uint32_t
handle_options(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse,
    uint32_t paramsCount
    )
{
    uint32_t dwError = 0;
    char* pszHttpMethod = NULL;
    char *pszURI = NULL;
    char pszDataLen[10] = {0};
    uint32_t done = 0;

    dwError =  VmRESTGetHttpMethod(pRequest, &pszHttpMethod);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_uri_from_request(pRequest, &pszURI);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(stdout, "%s for URI %s\n", pszHttpMethod, pszURI);

    dwError = VmRESTSetHttpHeader(
                  ppResponse,
                  "Access-Control-Allow-Methods",
                  "POST, GET, OPTIONS, PUT, DELETE"
                  );
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(
                  ppResponse,
                  "Access-Control-Allow-Headers",
                  "Origin, X-Requested-With, Content-Type, Accept, Authorization"
                  );
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(
                  ppResponse,
                  "Access-Control-Request-Methods",
                  "*"
                  );
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(
                  ppResponse,
                  "Access-Control-Allow-Origin",
                  "*"
                  );
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetSuccessResponse(pRequest, ppResponse);
    BAIL_ON_PMD_ERROR(dwError);

    sprintf(pszDataLen, "%d", 0);
    dwError = VmRESTSetDataLength(ppResponse, pszDataLen);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetData(
                      pRestHandle,
                      ppResponse,
                      "",
                      0,
                      &done
                      );
    BAIL_ON_PMD_ERROR(dwError);
cleanup:
    PMD_SAFE_FREE_MEMORY(pszURI);
    PMD_SAFE_FREE_MEMORY(pszHttpMethod);
    return dwError;

error:
    goto cleanup;
}
