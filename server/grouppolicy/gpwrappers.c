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

const char* gp_plugin_paths[] =
{
  "/etc/pmd/pmd.grouppolicy.plugins.d/libpmdgpmgmt.so",
  // Load the local policy plugin
  //TODO
  NULL
};

// Load the gp policy plugin and store the handle in a global variable
uint32_t
pmd_policy_plugin_load_interface(PPMD_POLICY_PLUGIN_INTERFACE *ppInterface)
{
    uint32_t dwError =0;

    char *pszVersion;
    
    //TODO: load the location of the libraies from the conf file
    //For now hardcode the path values of the libraries.
    
    PMDAllocateMemory(sizeof(PMD_POLICY_PLUGIN_INTERFACE),(void **)&gpServerEnv->gpGroupInterface);

    gpServerEnv->gpGroupInterface->hHandle = dlopen(gp_plugin_paths[0],RTLD_NOW);
    if(!gpServerEnv->gpGroupInterface->hHandle)
    {
    fprintf(stdout, "\n Group policy library load failed %s\n",dlerror());
    dwError = ERROR_PMD_GP_PKG_NOT_FOUND;
    BAIL_ON_PMD_ERROR(dwError);
    }
    
    gpServerEnv->gpGroupInterface->pFnPolicyVersion =dlsym(gpServerEnv->gpGroupInterface->hHandle,"pmd_gpmgmt_get_version");

    //Call the version function to check that the binding is ok
    gpServerEnv->gpGroupInterface->pFnPolicyVersion(&pszVersion);

    fprintf(stdout, "Group policy version is %s\n", pszVersion);


cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);
    goto cleanup;
}

uint32_t
pmd_policy_plugin_unload_interface(
    )
{
    uint32_t dwError =0;
    
    //Close the library
    if(gpServerEnv->gpGroupInterface->hHandle)
    {
    dwError = dlclose(gpServerEnv->gpGroupInterface->hHandle);
    if(dwError !=0)
      {
      dwError = ERROR_PMD_GP_PKG_UNLOAD_FAILED;
      goto error;

      }
    }
     
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);
    goto cleanup;

}
