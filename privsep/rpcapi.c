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
    PMD_SAFE_FREE_MEMORY(pszUserPass);
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    return dwError;

error:
    goto cleanup;
}
