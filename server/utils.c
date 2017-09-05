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
PPMDGetHostName(
    char** ppszHostName
)
{
    uint32_t dwError = 0;
    char pszHostBuf[HOST_NAME_MAX];
    uint32_t dwBufLen = sizeof(pszHostBuf) - 1;
    char* pszHostName = NULL;

    if (gethostname(pszHostBuf, dwBufLen) < 0)
    {
        dwError = errno;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszHostBuf, &pszHostName);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszHostName = pszHostName;

cleanup:
    return dwError;

error:
    if(ppszHostName)
    {
        *ppszHostName = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszHostName);
    goto cleanup;
}

uint32_t
PPMDGetCanonicalHostName(
    char* pszHostname,
    char** ppszCanonicalHostname
    )
{
    uint32_t  dwError = 0;
    struct addrinfo* pHostInfo = NULL;
    char szCanonicalHostname[NI_MAXHOST+1] = "";
    char*   pszCanonicalHostname = NULL;
    struct addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_CANONNAME;

    dwError = getaddrinfo(
                      pszHostname,
                      NULL,
                      &hints,
                      &pHostInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = getnameinfo(
                      pHostInfo->ai_addr,
                      (socklen_t)(pHostInfo->ai_addrlen),
                      szCanonicalHostname,
                      NI_MAXHOST,
                      NULL,
                      0,
                      NI_NAMEREQD);
    BAIL_ON_PMD_ERROR(dwError);

    if (!IsNullOrEmptyString(&szCanonicalHostname[0]))
    {
        dwError = PMDAllocateString(
                    &szCanonicalHostname[0],
                    &pszCanonicalHostname);
    }
    else
    {
        dwError = ERROR_NO_DATA;
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppszCanonicalHostname = pszCanonicalHostname;

cleanup:

    if (pHostInfo)
    {
        freeaddrinfo(pHostInfo);
    }

    return dwError;

error:

    *ppszCanonicalHostname = NULL;

    PMD_SAFE_FREE_MEMORY(pszCanonicalHostname);

    goto cleanup;
}

void
pmd_free_server_env(
    PSERVER_ENV pEnv
    )
{
    if(!pEnv)
    {
        return;
    }
    pthread_mutex_destroy(&gpServerEnv->mutexModuleEntries);
    pmd_free_config(gpServerEnv->pConfig);
    coapi_free_api_def(gpServerEnv->pApiDef);
    PMD_SAFE_FREE_MEMORY(gpServerEnv->pRestProcessor);
    free_security_context(gpServerEnv->pSecurityContext);
}
