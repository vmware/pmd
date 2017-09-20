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

/*
 * plugin load
*/
int
creds_plugin_load_interface(
    PCREDS_PLUGIN_INTERFACE *ppInterface
    )
{
    uint32_t dwError = 0;
    PCREDS_PLUGIN_INTERFACE pInterface = NULL;

    if(!ppInterface)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(CREDS_PLUGIN_INTERFACE),
                  (void **)&pInterface);
    BAIL_ON_PMD_ERROR(dwError);

    pInterface->pfnGetHashedCreds = privsepd_client_get_hashed_creds;
    *ppInterface = pInterface;

cleanup:
    return dwError;

error:
    if(ppInterface)
    {
        *ppInterface = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pInterface);
    goto cleanup;
}
