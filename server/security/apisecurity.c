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
init_security_config(
    const char *pszApiSecurityConf,
    PPMD_SECURITY_CONTEXT *ppContext
    )
{
    uint32_t dwError = 0;
    PCONF_DATA pData = NULL;
    PPMD_SECURITY_CONTEXT pContext = NULL;

    if(IsNullOrEmptyString(pszApiSecurityConf) || !ppContext)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_SECURITY_CONTEXT),
                                (void **)&pContext);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = read_config_file(pszApiSecurityConf,
                               MAX_API_SECURITY_LINE_LENGTH,
                               &pData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = init_module_security(pData, &pContext->pModuleSecurity);
    BAIL_ON_PMD_ERROR(dwError);

    *ppContext = pContext;

cleanup:
    free_config_data(pData);
    return dwError;

error:
    if(ppContext)
    {
        *ppContext = NULL;
    }
    free_security_context(pContext);
    goto cleanup;
}

uint32_t
save_security_config(
    const char *pszApiSecurityConf,
    PPMD_SECURITY_CONTEXT *ppContext
    )
{
    uint32_t dwError = 0;
    if(IsNullOrEmptyString(pszApiSecurityConf))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
init_module_security(
    PCONF_DATA pData,
    PPMD_MODULE_SECURITY *ppModuleSecurity
    )
{
    uint32_t dwError = 0;
    PPMD_MODULE_SECURITY pModuleSecurity = NULL;
    PPMD_MODULE_SECURITY pModuleTemp = NULL;
    PCONF_SECTION pSection = NULL;

    if(!pData || !ppModuleSecurity)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pSection = pData->pSections; pSection; pSection = pSection->pNext)
    {
        PKEYVALUE pKeyValue = NULL;
        dwError = PMDAllocateMemory(sizeof(PMD_MODULE_SECURITY),
                                    (void **)&pModuleTemp);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pSection->pszName,
                                    &pModuleTemp->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        for(pKeyValue = pSection->pKeyValues;
            pKeyValue;
            pKeyValue = pKeyValue->pNext) 
        {
            PPMD_API_SECURITY pApiSecurity = NULL;
            dwError = PMDAllocateMemory(sizeof(PMD_API_SECURITY),
                                        (void **)&pModuleTemp->pApiSecurity);
            BAIL_ON_PMD_ERROR(dwError);

            pApiSecurity = pModuleTemp->pApiSecurity;

            dwError = PMDAllocateString(pKeyValue->pszKey,
                                        &pApiSecurity->pszName);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = PMDAllocateString(pKeyValue->pszValue,
                                        &pApiSecurity->pszSDDL);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pModuleTemp->pNext = pModuleSecurity;
        pModuleSecurity = pModuleTemp;
        pModuleTemp = NULL;
    }

    *ppModuleSecurity = pModuleSecurity;

cleanup:
    return dwError;

error:
    if(ppModuleSecurity)
    {
        *ppModuleSecurity = NULL;
    }
    free_module_security(pModuleTemp);
    free_module_security(pModuleSecurity);
    goto cleanup;
}

uint32_t
find_module_api(
    PPMD_SECURITY_CONTEXT pContext,
    const char *pszModule,
    const char *pszApiName,
    PPMD_API_SECURITY *ppApiSecurity
    )
{
    uint32_t dwError = 0;
    PPMD_MODULE_SECURITY pModule = NULL;
    PPMD_API_SECURITY pApiSecurity = NULL;

    if(!pContext ||
       !pContext->pModuleSecurity ||
       IsNullOrEmptyString(pszModule) ||
       IsNullOrEmptyString(pszApiName) ||
       !ppApiSecurity)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pModule = pContext->pModuleSecurity;
    for(; pModule; pModule = pModule->pNext)
    {
        if(!strcmp(pModule->pszName, pszModule))
        {
            pApiSecurity = pModule->pApiSecurity;
            break;
        }
    }

    if(!pApiSecurity)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(; pApiSecurity; pApiSecurity = pApiSecurity->pNext)
    {
        if(!strcmp(pApiSecurity->pszName, pszApiName))
        {
            break;
        }
    }

    if(!pApiSecurity)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppApiSecurity = pApiSecurity;
cleanup:
    return dwError;

error:
    if(ppApiSecurity)
    {
        *ppApiSecurity = NULL;
    }
    goto cleanup;
}

void
free_api_security(
    PPMD_API_SECURITY pApiSecurity
    )
{
    if(!pApiSecurity)
    {
        return;
    }
    while(pApiSecurity)
    {
        PPMD_API_SECURITY pTemp = pApiSecurity->pNext;

        PMD_SAFE_FREE_MEMORY(pApiSecurity->pszName);
        PMD_SAFE_FREE_MEMORY(pApiSecurity->pszSDDL);
        PMD_SAFE_FREE_MEMORY(pApiSecurity);

        pApiSecurity = pTemp;
    }
}

void
free_module_security(
    PPMD_MODULE_SECURITY pModuleSecurity
    )
{
    if(!pModuleSecurity)
    {
        return;
    }
    while(pModuleSecurity)
    {
        PPMD_MODULE_SECURITY pTemp = pModuleSecurity->pNext;

        free_api_security(pModuleSecurity->pApiSecurity);
        PMD_SAFE_FREE_MEMORY(pModuleSecurity->pszName);
        PMD_SAFE_FREE_MEMORY(pModuleSecurity);

        pModuleSecurity = pTemp;
    }
}

void
free_security_context(
    PPMD_SECURITY_CONTEXT pContext
    )
{
    if(!pContext)
    {
        return;
    }
    free_module_security(pContext->pModuleSecurity);
    PMD_SAFE_FREE_MEMORY(pContext);
}
