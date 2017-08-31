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
populate_error(
    PVMREST_HANDLE pRestHandle,
    PREST_RESPONSE* ppResponse,
    PJWT_ERROR pError
    )
{
    uint32_t dwError = 0;
    char *pszCode = NULL;
    uint32_t temp = 0;

    if(!pRestHandle || !ppResponse || !pError)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(&pszCode, "%d", pError->nStatus);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpStatusVersion(ppResponse, "HTTP/1.1");
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpStatusCode(ppResponse, pszCode);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpReasonPhrase(ppResponse, pError->pszError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(ppResponse, "Connection", "close");
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpHeader(ppResponse, "Content-Length", "0");
    BAIL_ON_PMD_ERROR(dwError);

    dwError = VmRESTSetHttpPayload(pRestHandle, ppResponse, "", 0, &temp);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCode);
    return dwError;

error:
    goto cleanup;
}

uint32_t
process_auth(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    const char *pszPubKeyFile,
    PREST_RESPONSE* ppResponse
    )
{
    uint32_t dwError = 0;
    char* pszAuth = NULL;

    if(!pRestHandle || !pRequest || !ppResponse)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = VmRESTGetHttpHeader(pRequest, "Authorization", &pszAuth);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pszAuth)
    {
        dwError = ERROR_PMD_REST_AUTH_REQUIRED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(strstr(pszAuth, AUTH_NEGOTIATE))
    {
        dwError = verify_krb_auth(pRestHandle, pRequest, ppResponse);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(strstr(pszAuth, AUTH_BASIC))
    {
        dwError = verify_basic_auth(pRestHandle, pRequest, pszPubKeyFile, ppResponse);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = ERROR_PMD_REST_AUTH_BASIC_MIN;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    if(dwError == ERROR_PMD_REST_AUTH_REQUIRED ||
       dwError == ERROR_PMD_REST_AUTH_BASIC_MIN)
    {
        request_basic_auth(pRestHandle, pRequest, ppResponse);
    }
    goto cleanup;
}
