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
privsep_handle_list_add(
    PPMDHANDLE hPMD,
    PPKGHANDLE hPkg
    )
{
    uint32_t dwError = 0;
    PHPRIVSEP_TO_HPKG pEntry = NULL;
    int nLocked = 0;

    if(!gpServerEnv || !hPMD || !hPkg)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(HPRIVSEP_TO_HPKG), (void **)&pEntry);
    BAIL_ON_PMD_ERROR(dwError);

    pEntry->hPMD = hPMD;
    pEntry->hPkg = hPkg;

    pthread_mutex_lock(&gpServerEnv->mutexPrivSepHandleList);
    nLocked = 1;

    if(!gpServerEnv->gpPrivSepHandleList)
    {
        gpServerEnv->gpPrivSepHandleList = pEntry;
    }
    else
    {
        PHPRIVSEP_TO_HPKG pTemp = gpServerEnv->gpPrivSepHandleList;
        while(pTemp->pNext) pTemp = pTemp->pNext;
        pTemp->pNext = pEntry;
    }

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPrivSepHandleList);
        nLocked = 0;
    }
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pEntry);
    goto cleanup;
}

uint32_t
privsep_handle_list_get(
    PPKGHANDLE hPkg,
    PPMDHANDLE *phPMD
    )
{
    uint32_t dwError = 0;
    PHPRIVSEP_TO_HPKG pEntry = NULL;
    PHPRIVSEP_TO_HPKG pTemp = NULL;
    PPMDHANDLE hPMD = NULL;
    int nLocked = 0;

    if(!gpServerEnv || !hPkg || !phPMD)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPrivSepHandleList);
    nLocked = 1;

    if(!gpServerEnv->gpPrivSepHandleList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pTemp = gpServerEnv->gpPrivSepHandleList; pTemp; pTemp = pTemp->pNext)
    {
        if(pTemp->hPkg == hPkg)
        {
            hPMD = pTemp->hPMD;
            break;
        }
    }

    if(!hPMD)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *phPMD = hPMD;
cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPrivSepHandleList);
        nLocked = 0;
    }
    return dwError;

error:
    if(phPMD)
    {
        *phPMD = NULL;
    }
    goto cleanup;
}

uint32_t
privsep_handle_list_remove(
    PPKGHANDLE hPkg,
    PPMDHANDLE *phPMD
    )
{
    uint32_t dwError = 0;
    PHPRIVSEP_TO_HPKG pTemp = NULL;
    PHPRIVSEP_TO_HPKG pPrev = NULL;
    PPMDHANDLE hPMD = NULL;
    int nLocked = 0;

    if(!gpServerEnv || !hPkg || !phPMD)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gpServerEnv->mutexPrivSepHandleList);
    nLocked = 1;

    if(!gpServerEnv->gpPrivSepHandleList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pPrev = NULL, pTemp = gpServerEnv->gpPrivSepHandleList;
        pTemp;
        pPrev = pTemp, pTemp = pTemp->pNext)
    {
        if(pTemp->hPkg == hPkg)
        {
            hPMD = pTemp->hPMD;
            break;
        }
    }

    if(!hPMD)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pPrev)
    {
        gpServerEnv->gpPrivSepHandleList = pTemp->pNext;
    }
    else
    {
        pPrev->pNext = pTemp->pNext;
    }
    PMD_SAFE_FREE_MEMORY(pTemp);

    *phPMD = hPMD;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gpServerEnv->mutexPrivSepHandleList);
        nLocked = 0;
    }
    return dwError;

error:
    if(phPMD)
    {
        *phPMD = NULL;
    }
    goto cleanup;
}
