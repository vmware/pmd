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
    char **ppszVersion)
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if (!ppszVersion)
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
    if (ppszVersion)
    {
        *ppszVersion = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_gpmgmt_start_policies()
{
    uint32_t dwError = 0;
    PPMD_POLICY_DATA pPolicies = NULL;

    dwError = pmd_gpmgmt_load_policies(&pPolicies);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(stdout, "Loaded the policies successfully\n");
    pmd_gpmgmt_create_policy_json();

    fprintf(stdout, "Created the policy json \n");
    dwError = pmd_gpmgmt_print_polices(pPolicies);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(stdout, "Enforcing the loaded polices \n");
    dwError = pmd_gpmgmt_enforce_polices(pPolicies);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    gpmgmt_free_policies(pPolicies);
    return dwError;

error:
    fprintf(stderr, "Starting policies failed  \n");
    goto cleanup;
}

uint32_t
pmd_gpmgmt_execute_polices(
    const PPMD_POLICY_DATA pPolicies,
    const PMD_POLICY_KIND nPolicyKind)
{
    uint32_t dwError = 0;
    PPMD_POLICY_DATA pPolicy = NULL;
    pPolicy = pPolicies;

    if(!pPolicies)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(nPolicyKind < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fprintf(stdout, "In the executing of policies thread \n");

    while (pPolicy)
    {
        if (pPolicy->nKind != nPolicyKind)
        {
            pPolicy = pPolicy->pNext;
            continue;
        }

        if (!strcmp(pPolicy->pszPolicyName, "updatepolicy") ||
            !strcmp(pPolicy->pszPolicyName, "downgradepolicy"))
        {
            fprintf(stdout, "Executing %s  policy\n", pPolicy->pszPolicyName);
            dwError = pmd_gpmgmt_execute_updatepolicy(pPolicy);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else
        {
            fprintf(stdout, "Unknown  %s  policy!!! --skipping\n", pPolicy->pszPolicyName);
            dwError = ERROR_PMD_GPMGMT_UNKNOWN_POLICY;
            BAIL_ON_PMD_ERROR(dwError);
        }

        pPolicy = pPolicy->pNext;
    }

cleanup:
    return dwError;

error:
    fprintf(stderr, "Executing policies failed  \n");
    goto cleanup;
}

void *
pmd_gpmgmt_enforcement_thread(
    void *args)
{
    uint32_t dwError = 0;
    PPMD_POLICY_DATA pPolicies = (PPMD_POLICY_DATA)args;
    gpServerEnv->gpGroupInterface->enforcePolices = 1;
    // TODO: if we get a kill signal from stop polices stop enforcing polices
    // Handle signals
    // Kill signals
    // TODO: Open an sqllite db
    // Open handle for logging
    fprintf(stdout, "In the policy enforcement thread \n");

    while (gpServerEnv->gpGroupInterface->enforcePolices)
    {
        // Enforce local policies first
        dwError = pmd_gpmgmt_execute_polices(pPolicies, POLICY_KIND_LOCAL);
        BAIL_ON_PMD_ERROR(dwError);
        // Enforce site polices next
        dwError = pmd_gpmgmt_execute_polices(pPolicies, POLICY_KIND_SITE);
        BAIL_ON_PMD_ERROR(dwError);

        gpServerEnv->gpGroupInterface->enforcePolices--;
        //sleep();
    }

cleanup:
    return NULL;

error:
    goto cleanup;
}

uint32_t
pmd_gpmgmt_enforce_polices(
    const PPMD_POLICY_DATA pPolicies)
{
    uint32_t dwError = 0;
    pthread_t pid;

    if (!pPolicies)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    // Create a thread to handle the policies
    //dwError = pthread_create(&pid, NULL, pmd_gpmgmt_enforcement_thread, pPolicies);
    pmd_gpmgmt_enforcement_thread(pPolicies);

    //BAIL_ON_PMD_ERROR(dwError);

    //pthread_join(pid, status);

cleanup:
    return dwError;

error:
    goto cleanup;
}
