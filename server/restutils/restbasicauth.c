/*
 * Copyright © 2019 VMware, Inc.  All Rights Reserved.
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

/*
HTTP/1.1 401 Authorization Required
WWW-Authenticate: Basic realm="Photon Management Daemon"
Content-Type: text/html
Content-Length: 20
*/

uint32_t
request_basic_auth(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    )
{
    uint32_t dwError = 0;
    uint32_t temp = 0;

    dwError = VmRESTSetHttpStatusVersion(ppResponse, "HTTP/1.1");
    dwError = VmRESTSetHttpStatusCode(ppResponse, "401");
    dwError = VmRESTSetHttpReasonPhrase(ppResponse, "Unauthorized");
    dwError = VmRESTSetHttpHeader(ppResponse, "Connection", "close");
    dwError = VmRESTSetHttpHeader(ppResponse, "Content-Length", "0");
    dwError = VmRESTSetHttpHeader(ppResponse, "WWW-Authenticate", "Basic realm=\"Photon Management Daemon\"");
    dwError = VmRESTSetHttpPayload(pRestHandle, ppResponse,"", 0, &temp );
    dwError = EACCES;
    return dwError;
}

uint32_t
verify_basic_auth(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    )
{
    uint32_t dwError = 0;
    char* pszAuth = NULL;
    const char* BASIC_AUTH_STRING = "Basic ";
    char* pszUserPassBase64 = NULL;
    char* pszUserPass = NULL;
    char* pszUser = NULL;
    char* pszPass = NULL;
    int nLength = 0;
    uint32_t nValid = 0;

    dwError = VmRESTGetHttpHeader(pRequest, "Authorization", &pszAuth);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pszAuth)
    {
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!strstr(pszAuth, BASIC_AUTH_STRING))
    {
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszUserPassBase64 = pszAuth + strlen(BASIC_AUTH_STRING);
    if(IsNullOrEmptyString(pszUserPassBase64))
    {
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = base64_decode(pszUserPassBase64, &pszUserPass, &nLength);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = split_user_and_pass(pszUserPass, &pszUser, &pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    //validate local user/pass
    dwError = pmd_check_password(pszUser, pszPass, &nValid);
    BAIL_ON_PMD_ERROR(dwError);

    if(!nValid)
    {
        fprintf(stderr, "REST basic auth fail for user: %s\n", pszUser);
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszUserPass);
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    return dwError;

error:
    if(dwError == EACCES || dwError == ERROR_PMD_ACCESS_DENIED)
    {
        request_basic_auth(pRestHandle, pRequest, ppResponse);
    }
    goto cleanup;
}
