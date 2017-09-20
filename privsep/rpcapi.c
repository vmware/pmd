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
#include <gssapi_creds_plugin.h>
#include <dlfcn.h>

unsigned32
privsepd_rpc_unix_auth(
    handle_t hBinding,
    wstring_t pwszUser,
    wstring_t *ppwszSalt,
    wstring_t *ppwszB64SValue,
    wstring_t *ppwszB64VValue
    )
{
    uint32_t dwError = 0;
    char *pszUser = NULL;
    char *pszSalt = NULL;
    unsigned char *bytes_s = NULL;
    int len_s = 0;
    unsigned char *bytes_v = NULL;
    int len_v = 0;
    wstring_t pwszSalt = NULL;
    wstring_t pwszB64SValue = NULL;
    wstring_t pwszB64VValue = NULL;
    char *pszB64SValue = NULL;
    char *pszB64VValue = NULL;
    void *hCreds = NULL;
    PFN_GET_HASHED_CREDS pfnGetHashedCreds = NULL;

    if(!hBinding ||
       !pwszUser ||
       !ppwszSalt ||
       !ppwszB64SValue ||
       !ppwszB64VValue)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszUser, &pszUser);
    BAIL_ON_PMD_ERROR(dwError);

    hCreds = dlopen(GSSAPI_UNIX_CREDS_DEFAULT_SO, RTLD_NOW);
    if(!hCreds)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pfnGetHashedCreds = (PFN_GET_HASHED_CREDS)
                        dlsym(hCreds, "get_salt_and_v_value");
    if(!pfnGetHashedCreds)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pfnGetHashedCreds(
                  PLUGIN_TYPE_UNIX,
                  pszUser,
                  &pszSalt,
                  &bytes_s,
                  &len_s,
                  &bytes_v,
                  &len_v);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszSalt, &pwszSalt);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_encode(bytes_s, len_s, &pszB64SValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_decode(pszB64SValue, &bytes_s, &len_s);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszB64SValue, &pwszB64SValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_encode(bytes_v, len_v, &pszB64VValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszB64VValue, &pwszB64VValue);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszSalt = pwszSalt;
    *ppwszB64SValue = pwszB64SValue;
    *ppwszB64VValue = pwszB64VValue;

cleanup:
    if(hCreds)
    {
        dlclose(hCreds);
    }
    PMD_SAFE_FREE_MEMORY(bytes_s);
    PMD_SAFE_FREE_MEMORY(bytes_v);
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszSalt);
    PMD_SAFE_FREE_MEMORY(pszB64SValue);
    PMD_SAFE_FREE_MEMORY(pszB64VValue);
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pwszSalt);
    PMD_SAFE_FREE_MEMORY(pwszB64SValue);
    PMD_SAFE_FREE_MEMORY(pwszB64VValue);
    goto cleanup;
}
