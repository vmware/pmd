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
privsepd_client_basic_auth(
    PPMDHANDLE hHandle,
    const char *pszBasicAuth,
    const char *pszContext,
    unsigned32 *pnValid
    )
{
    uint32_t dwError = 0;
    wstring_t pwszBasicAuth = NULL;
    wstring_t pwszContext = NULL;
    unsigned32 nValid = 0;

    if(!hHandle ||
       IsNullOrEmptyString(pszBasicAuth) ||
       IsNullOrEmptyString(pszContext))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszBasicAuth,
                  &pwszBasicAuth);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(
                  pszContext,
                  &pwszContext);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(privsepd_rpc_basic_auth(
               hHandle->hRpc,
               pwszBasicAuth,
               pwszContext,
               &nValid), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    *pnValid = nValid;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszBasicAuth);
    PMD_SAFE_FREE_MEMORY(pwszContext);
    return dwError;

error:
    if(pnValid)
    {
        *pnValid = 0;
    }
    goto cleanup;
}

uint32_t
privsepd_client_unix_creds_hash(
    PPMDHANDLE hHandle,
    const char *pszUser,
    char **ppszSalt,
    unsigned char **pbytes_s,
    int *plen_s,
    unsigned char **pbytes_v,
    int *plen_v
    )
{
    uint32_t dwError = 0;
    wstring_t pwszUser = NULL;
    wstring_t pwszSalt = NULL;
    wstring_t pwszB64VValue = NULL;
    wstring_t pwszB64SValue = NULL;
    unsigned char *bytes_v = NULL;
    unsigned char *bytes_s = NULL;
    int len_v = 0;
    int len_s = 0;
    char *pszSalt = NULL;
    char *pszB64VValue = NULL;
    char *pszB64SValue = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszUser))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(
                  pszUser,
                  &pwszUser);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(privsepd_rpc_unix_auth(
               hHandle->hRpc,
               pwszUser,
               &pwszSalt,
               &pwszB64SValue,
               &pwszB64VValue), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszSalt,
                  &pszSalt);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszB64SValue,
                  &pszB64SValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_decode(pszB64SValue, (char **)&bytes_s, &len_s);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszB64VValue,
                  &pszB64VValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_decode(pszB64VValue, (char **)&bytes_v, &len_v);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszSalt = pszSalt;
    *pbytes_s = bytes_s;
    *plen_s = len_s;
    *pbytes_v = bytes_v;
    *plen_v = len_v;

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszUser);
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pszSalt);
    goto cleanup;
}

uint32_t
rpc_open_privsep_internal(
    const char *pszModule,
    PPMDHANDLE* phHandle
    );

uint32_t
privsepd_client_get_hashed_creds(
    const char *pszUser,
    char **ppszSalt,
    unsigned char **pbytes_s,
    int *plen_s,
    unsigned char **pbytes_v,
    int *plen_v
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hHandle = NULL;
    if(!pszUser)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rpc_open_privsep_internal("privsepd", &hHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = privsepd_client_unix_creds_hash(
                  hHandle,
                  pszUser,
                  ppszSalt,
                  pbytes_s,
                  plen_s,
                  pbytes_v,
                  plen_v);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hHandle);
    return dwError;
error:
    goto cleanup;
}
