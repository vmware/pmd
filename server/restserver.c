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
StartRestServer(
    )
{
    uint32_t dwError = 0;
    PREST_API_DEF pApiDef = NULL;
    PREST_PROCESSOR pRestProcessor = NULL;
    PPMD_REST_CONFIG pRestConfig = NULL;

    MODULE_REG_MAP stRegMap[] =
    {

#ifdef DEMO_ENABLED
        {"demo", demo_rest_get_registration},
#endif

        {"firewall", firewall_rest_get_registration},
        {"net",     net_rest_get_registration},
        {"pkg",     pkg_rest_get_registration},
        {"pmd",     pmd_rest_get_registration},
        {"rolemgmt",rolemgmt_rest_get_registration},
        {"usrmgmt", usrmgmt_rest_get_registration},

        {NULL, NULL}
    };

    pRestConfig = gpServerEnv->pConfig->pRestConfig;
    if(!pRestConfig && IsNullOrEmptyString(pRestConfig->pszApiSpec))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError =  VmRESTInit(
                   NULL,
                   "/etc/pmd/restconfig.txt",
                   &gpServerEnv->pRestHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = coapi_load_from_file(pRestConfig->pszApiSpec, &pApiDef);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = coapi_map_api_impl(pApiDef, stRegMap);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rest_register_api_spec(
                  gpServerEnv->pRestHandle,
                  pApiDef,
                  &pRestProcessor);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_lock (&gpServerEnv->mutexModuleEntries);

    gpServerEnv->pApiDef = pApiDef;
    gpServerEnv->pRestProcessor = pRestProcessor;

    pthread_mutex_unlock (&gpServerEnv->mutexModuleEntries);

    dwError = VmRESTStart(gpServerEnv->pRestHandle);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(stdout, "started rest server.\n");
cleanup:
    return dwError;

error:
    fprintf(stdout, "rest server start failed. error: %d\n", dwError);
    goto cleanup;
}

void
StopRestServer()
{
    fprintf(stdout, "Stopping rest server.\n");
    if(!gpServerEnv || !gpServerEnv->pRestHandle)
    {
        fprintf(stdout, "rest server not started. skipping stop.\n");
        return;
    }
    VmRESTStop(gpServerEnv->pRestHandle);
    gpServerEnv->pRestHandle = NULL;
    fprintf(stdout, "stopped rest server.\n");
}
