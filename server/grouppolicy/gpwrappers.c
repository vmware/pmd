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
pmd_policy_plugin_load_interface(PPMD_POLICY_PLUGIN_INTERFACE *ppInterface)
{
    uint32_t dwError = 0;
    char *pszVersion;
    char *pszGpmgmtPluginPath;

    dlerror();
    PMDAllocateMemory(sizeof(PMD_POLICY_PLUGIN_INTERFACE), 
                     (void **)&gpServerEnv->gpGroupInterface);
    dwError = pmd_gpmgmt_get_val_from_key(PMD_CONFIG_FILE_NAME,
                                          PMD_CONFIG_GP_GROUP,
                                          PMD_CONFIG_KEY_GPMGMT_PLUGIN_PATH, 
                                          &pszGpmgmtPluginPath);
    BAIL_ON_PMD_ERROR(dwError);

    gpServerEnv->gpGroupInterface->hHandle = dlopen(pszGpmgmtPluginPath, RTLD_LAZY | RTLD_GLOBAL);
    if (!gpServerEnv->gpGroupInterface->hHandle)
    {
        fprintf(stderr, "\n Group policy library load failed %s\n", dlerror());
        dwError = ERROR_PMD_GPMGMT_PLUGIN_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpServerEnv->gpGroupInterface->pFnPolicyVersion = dlsym(
                                    gpServerEnv->gpGroupInterface->hHandle,
                                    "pmd_gpmgmt_get_version");
    gpServerEnv->gpGroupInterface->pFnStartPolicies = dlsym(
                                    gpServerEnv->gpGroupInterface->hHandle,
                                    "pmd_gpmgmt_start_policies");
    if (!gpServerEnv->gpGroupInterface->pFnStartPolicies || 
        !gpServerEnv->gpGroupInterface->pFnStartPolicies)
    {
        fprintf(stderr, "\n Group policy symbols not found %s\n", dlerror());
        dwError = ERROR_PMD_GPMGMT_SYMBOL_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpServerEnv->gpGroupInterface->pFnPolicyVersion(&pszVersion);
    if (IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    fprintf(stdout, "Group policy version is %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);
    goto cleanup;
}

uint32_t
pmd_policy_plugin_unload_interface()
{
    uint32_t dwError = 0;
    //Close the library
    if (gpServerEnv->gpGroupInterface->hHandle)
    {
        dwError = dlclose(gpServerEnv->gpGroupInterface->hHandle);
        if (dwError != 0)
        {
            dwError = ERROR_PMD_GPMGMT_PLUGIN_UNLOAD_FAILED;
            goto error;
        }
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);
    return dwError;

error:
    goto cleanup;
}


