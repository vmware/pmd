/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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

void
pmd_free_rest_config(
    PPMD_REST_CONFIG pRestConf
    );

uint32_t
pmd_get_rest_config(
    PCONF_DATA pData,
    PPMD_REST_CONFIG *ppRestConfig
    )
{
    uint32_t dwError = 0;
    PCONF_SECTION pSection = NULL;
    PKEYVALUE pKeyValues = NULL;
    PPMD_REST_CONFIG pRestConfig = NULL;

    if(!pData || !ppRestConfig)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = config_get_section(pData, PMD_CONFIG_REST_GROUP, &pSection);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_REST_CONFIG),
                               (void **)&pRestConfig);
    BAIL_ON_PMD_ERROR(dwError);

    //set defaults
    pRestConfig->nWorkerThreadCount = PMD_REST_DEFAULT_WORKER_THREAD;
    pRestConfig->nClientCount = PMD_REST_DEFAULT_CLIENTS;
    dwError = PMDAllocateString(PMD_REST_DEFAULT_SSL_CERT,
                                &pRestConfig->pszSSLCert);
    BAIL_ON_PMD_ERROR(dwError);
    dwError = PMDAllocateString(PMD_REST_DEFAULT_SSL_KEY,
                                &pRestConfig->pszSSLKey);

    BAIL_ON_PMD_ERROR(dwError);
    dwError = PMDAllocateString(PMD_REST_DEFAULT_LOG_FILE,
                                &pRestConfig->pszLogFile);
    BAIL_ON_PMD_ERROR(dwError);


    pKeyValues = pSection->pKeyValues;
    for(; pKeyValues; pKeyValues = pKeyValues->pNext)
    {
        if(!strcmp(PMD_CONFIG_KEY_REST_ENABLED, pKeyValues->pszKey))
        {
            pRestConfig->nEnabled = atoi(pKeyValues->pszValue);
        }
        else if(!strcmp(PMD_CONFIG_KEY_REST_PORT, pKeyValues->pszKey))
        {
            pRestConfig->nPort = atoi(pKeyValues->pszValue);
        }
	else if(!strcmp(PMD_CONFIG_KEY_REST_WORKER_THREAD_COUNT,
                        pKeyValues->pszKey))
        {
            pRestConfig->nWorkerThreadCount = atoi(pKeyValues->pszValue);
        }
        else if(!strcmp(PMD_CONFIG_KEY_REST_CLIENT_COUNT,
                        pKeyValues->pszKey))
        {
            pRestConfig->nClientCount = atoi(pKeyValues->pszValue);
        }
        else if(!strcmp(PMD_CONFIG_KEY_REST_APISPEC, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pRestConfig->pszApiSpec);
            BAIL_ON_PMD_ERROR(dwError);
        }
	else if(!strcmp(PMD_CONFIG_KEY_REST_SSL_CERT, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pRestConfig->pszSSLCert);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(PMD_CONFIG_KEY_REST_SSL_KEY, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pRestConfig->pszSSLKey);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(PMD_CONFIG_KEY_REST_LOG_FILE, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pRestConfig->pszLogFile);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(PMD_CONFIG_KEY_REST_AUTH, pKeyValues->pszKey))
        {
            pRestConfig->nUseKerberos =
                strcmp(pKeyValues->pszValue, "kerberos") == 0;
        }
    }

    *ppRestConfig = pRestConfig;

cleanup:
    return dwError;

error:
    if(ppRestConfig)
    {
        *ppRestConfig = NULL;
    }
    pmd_free_rest_config(pRestConfig);
    goto cleanup;
}

uint32_t
pmd_get_roles_config(
    PCONF_DATA pData,
    PPMD_ROLES_CONFIG *ppRolesConfig
    )
{
    uint32_t dwError = 0;
    PCONF_SECTION pSection = NULL;
    PKEYVALUE pKeyValues = NULL;
    PPMD_ROLES_CONFIG pRolesConfig = NULL;

    if(!pData || !ppRolesConfig)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = config_get_section(pData, PMD_CONFIG_ROLES_GROUP, &pSection);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_ROLES_CONFIG),
                               (void **)&pRolesConfig);
    BAIL_ON_PMD_ERROR(dwError);

    pKeyValues = pSection->pKeyValues;
    for(; pKeyValues; pKeyValues = pKeyValues->pNext)
    {
        if(!strcmp(PMD_CONFIG_KEY_ROLES_DIR, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pRolesConfig->pszDir);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(PMD_CONFIG_KEY_ROLES_PLUGINSDIR, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pRolesConfig->pszPluginsDir);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppRolesConfig = pRolesConfig;

cleanup:
    return dwError;

error:
    if(ppRolesConfig)
    {
        *ppRolesConfig = NULL;
    }
    pmd_free_roles_config(pRolesConfig);
    goto cleanup;
}

uint32_t
pmd_read_config(
    const char* pszFile,
    const char* pszGroup,
    PPMD_CONFIG* ppConf
    )
{
    uint32_t dwError = 0;
    PPMD_CONFIG pConf = NULL;
    PCONF_DATA pData = NULL;
    PCONF_SECTION pSection = NULL;
    PKEYVALUE pKeyValues = NULL;

    if(IsNullOrEmptyString(pszFile) ||
       IsNullOrEmptyString(pszGroup) ||
       !ppConf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = read_config_file(pszFile, 0, &pData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_CONFIG), (void **)&pConf);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = config_get_section(pData, pszGroup, &pSection);
    BAIL_ON_PMD_ERROR(dwError);

    pKeyValues = pSection->pKeyValues;
    for(; pKeyValues; pKeyValues = pKeyValues->pNext)
    {
        if(!strcmp(PMD_CONFIG_KEY_SERVERTYPE, pKeyValues->pszKey))
        {
            pConf->nServerType = atoi(pKeyValues->pszValue);
        }
        if(!strcmp(PMD_CONFIG_KEY_API_SECURITY, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pConf->pszApiSecurityConf);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = config_get_section(pData, PMD_CONFIG_PRIVSEP_GROUP, &pSection);
    BAIL_ON_PMD_ERROR(dwError);

    pKeyValues = pSection->pKeyValues;
    for(; pKeyValues; pKeyValues = pKeyValues->pNext)
    {
        if(!strcmp(PMD_CONFIG_KEY_PRIVSEP_PUBKEY, pKeyValues->pszKey))
        {
            dwError = PMDAllocateString(pKeyValues->pszValue,
                                        &pConf->pszPrivsepPubKeyFile);
            BAIL_ON_PMD_ERROR(dwError);

            break;//need just the pub key
        }
    }

    dwError = pmd_get_rest_config(pData, &pConf->pRestConfig);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_get_roles_config(pData, &pConf->pRolesConfig);
    BAIL_ON_PMD_ERROR(dwError);

    *ppConf = pConf;

cleanup:
    free_config_data(pData);
    return dwError;

error:
    if(ppConf)
    {
        *ppConf = NULL;
    }
    pmd_free_config(pConf);
    goto cleanup;
}

void
pmd_free_rest_config(
    PPMD_REST_CONFIG pRestConf
    )
{
    if(!pRestConf)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pRestConf->pszApiSpec);
    PMD_SAFE_FREE_MEMORY(pRestConf->pszLogFile);
    PMD_SAFE_FREE_MEMORY(pRestConf->pszSSLCert);
    PMD_SAFE_FREE_MEMORY(pRestConf->pszSSLKey);
    PMD_SAFE_FREE_MEMORY(pRestConf);
}

void
pmd_free_roles_config(
    PPMD_ROLES_CONFIG pRolesConf
    )
{
    if(!pRolesConf)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pRolesConf->pszDir);
    PMD_SAFE_FREE_MEMORY(pRolesConf->pszPluginsDir);
    PMD_SAFE_FREE_MEMORY(pRolesConf);
}

void
pmd_free_config(
    PPMD_CONFIG pConf
    )
{
    if(!pConf)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pConf->pszCurrentHash);
    PMD_SAFE_FREE_MEMORY(pConf->pszServerUrl);
    PMD_SAFE_FREE_MEMORY(pConf->pszComposeServer);
    PMD_SAFE_FREE_MEMORY(pConf->pszApiSecurityConf);
    pmd_free_rest_config(pConf->pRestConfig);
    PMD_SAFE_FREE_MEMORY(pConf->pszPrivsepPubKeyFile);
    pmd_free_roles_config(pConf->pRolesConfig);
    PMD_SAFE_FREE_MEMORY(pConf);
}
