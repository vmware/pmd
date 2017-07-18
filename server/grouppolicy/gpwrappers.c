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
  // Load the policy enforcement agent plugin
  "/root/temp/pmd/server/grouppolicy/gpmgmtplugin/.libs/libpmdgpmgmt.so",
  // Load the local policy plugin
  //TODO
  NULL
};

// Load the gp policy plugin and store the handle in a global variable
uint32_t
pmd_policy_plugin_load_interface(PPMD_POLICY_PLUGIN_INTERFACE *ppInterface)
{
    uint32_t dwError =0;

    //Allocate a char pointer for getting the version
    char *pszVersion;
    
    //TODO: load the location of the libraies from the conf file
    //For now hardcode the path values of the libraries.
    
    void * handle = NULL;
    
    // Open the shared library dynamically
    handle = dlopen(gp_plugin_paths[0],RTLD_NOW);
    if(!handle)
    {
    fprintf(stdout, "\n Group policy library load failed %s\n",dlerror());
    dwError = ERROR_PMD_GP_PKG_NOT_FOUND;
    BAIL_ON_PMD_ERROR(dwError);
    }
    
    //fprintf(stdout, "\n Group policy library load success \n");

    PMDAllocateMemory(sizeof(PMD_POLICY_PLUGIN_INTERFACE),(void **)&gpGroupInterface);
    
    gpGroupInterface->pFnPolicyVersion =dlsym(handle,"pmd_gpmgmt_get_version");

    //Call the version function to check that the binding is ok
    gpGroupInterface->pFnPolicyVersion(&pszVersion);

    fprintf(stdout, "Group policy version is %s\n", pszVersion);


cleanup:
    return dwError;

error:
    goto cleanup;
}
