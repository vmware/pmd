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
pmd_gpmgmt_get_version(
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString("0.1", &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_gpmgmt_start_policies(
    )
{   
    uint32_t dwError =0;
    PPMD_POLICY_DATA pPolicies= NULL;
    
    dwError = pmd_gpmgmt_load_policies(&pPolicies);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(stdout,"Loaded the policies successfully\n");
    pmd_gpmgmt_create_policy_json();

    fprintf(stdout,"Created the policy json correctly\n");
    dwError = pmd_gpmgmt_print_polices(pPolicies);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    gpmgmt_free_policies(pPolicies);
    return dwError;

error:
    gpmgmt_free_policies(pPolicies);
    goto cleanup;
}
