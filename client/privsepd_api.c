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
