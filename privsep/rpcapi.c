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
#include <dlfcn.h>

unsigned32
privsepd_rpc_basic_auth(
    handle_t hBinding,
    wstring_t pwszBasicAuth,
    wstring_t pwszContext,
    unsigned32 *pnValid
    )
{
    uint32_t dwError = 0;
    char *pszBasicAuth = NULL;
    char *pszContext = NULL;
    char* pszUserPass = NULL;
    char* pszUser = NULL;
    char* pszPass = NULL;
    char* pszEncrypted = NULL;
    int nEncryptedLength = 0;
    uint32_t nValid = 0;

    if(!hBinding || !pwszBasicAuth || !pwszContext)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszBasicAuth, &pszBasicAuth);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszContext, &pszContext);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_decode(pszBasicAuth, &pszEncrypted, &nEncryptedLength);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rsa_private_decrypt(
                  (unsigned char *)pszEncrypted,
                  nEncryptedLength,
                  "/etc/pmd/privsep_priv.key",
                  (unsigned char **)&pszUserPass);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = split_user_and_pass(pszUserPass, &pszUser, &pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    //validate local user/pass
    dwError = pmd_check_password(pszUser, pszPass, &nValid);
    BAIL_ON_PMD_ERROR(dwError);

    *pnValid = nValid;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszBasicAuth);
    PMD_SAFE_FREE_MEMORY(pszContext);
    PMD_SAFE_FREE_MEMORY(pszEncrypted);
    PMD_SAFE_FREE_MEMORY(pszUserPass);
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    return dwError;

error:
    if(pnValid)
    {
        *pnValid = 0;
    }
    goto cleanup;
}

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
    void *hCreds = NULL;
typedef
int
(*PFN_GET_HASHED_CREDS)(
    const char *user_name,
    char **ret_salt,
    unsigned char **ret_bytes_s,
    int *ret_len_s,
    unsigned char **ret_bytes_v,
    int *ret_len_v
    );

PFN_GET_HASHED_CREDS pfn = NULL;
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

    hCreds = dlopen("libgssapi_unix_creds_provider.so", RTLD_NOW);
    if(!hCreds)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pfn = (PFN_GET_HASHED_CREDS)dlsym(hCreds, "get_salt_and_v_value");
    if(!pfn)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pfn(pszUser, &pszSalt, &bytes_s, &len_s, &bytes_v, &len_v);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszSalt, &pwszSalt);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_encode(bytes_s, len_s, &pszB64SValue);
    BAIL_ON_PMD_ERROR(dwError);
    dwError = base64_decode(pszB64SValue, (char **)&bytes_s, &len_s);
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
    PMD_SAFE_FREE_MEMORY(pszUser);
    return dwError;

error:
    goto cleanup;
}
