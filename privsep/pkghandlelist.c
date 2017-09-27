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
pkg_handle_list_add(
    PTDNF pTdnf
    )
{
    uint32_t dwError = 0;
    PPKG_HANDLE_LIST pEntry = NULL;

    if(!gpServerEnv || !pTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PKG_HANDLE_LIST), (void **)&pEntry);
    BAIL_ON_PMD_ERROR(dwError);

    pEntry->pTdnf = pTdnf;

    pthread_mutex_lock(&gpServerEnv->mutexPkgHandleList);

    pEntry->pNext = gpServerEnv->gpPkgHandleList;
    gpServerEnv->gpPkgHandleList = pEntry;

    pthread_mutex_unlock(&gpServerEnv->mutexPkgHandleList);

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pEntry);
    goto cleanup;
}

uint32_t
privsep_handle_list_remove(
    PTDNF pTdnf
    )
{
    uint32_t dwError = 0;
    PPKG_HANDLE_LIST pTemp = NULL;
    PPKG_HANDLE_LIST pPrev = NULL;
    int nFound = 0;
    int nLocked = 0;

    if(!gpServerEnv || !pTdnf)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPkgHandleList);
    nLocked = 1;

    for(pPrev = NULL, pTemp = gpServerEnv->gpPkgHandleList;
        pTemp;
        pPrev = pTemp, pTemp = pTemp->pNext)
    {
        if(pTemp->pTdnf == pTdnf)
        {
            nFound = 1;
            break;
        }
    }

    if(!nFound)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pPrev)
    {
        gpServerEnv->gpPkgHandleList = pTemp->pNext;
    }
    else
    {
        pPrev->pNext = pTemp->pNext;
    }
    PMD_SAFE_FREE_MEMORY(pTemp);

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPkgHandleList);
        nLocked = 0;
    }
    return dwError;

error:
    goto cleanup;
}
