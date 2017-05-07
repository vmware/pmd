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

int
PMDIsSystemError(
    uint32_t dwError
    )
{
    return dwError >= ERROR_PMD_SYSTEM_BASE && dwError <= ERROR_PMD_SYSTEM_END;
}

uint32_t
PMDGetSystemErrorString(
    uint32_t dwSystemError,
    char** ppszError
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;
    char* pszSystemError = NULL;

    if(!ppszError || !PMDIsSystemError(dwSystemError))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(PMDIsSystemError(dwSystemError))
    {
        dwSystemError = dwSystemError - ERROR_PMD_SYSTEM_BASE;
        pszSystemError = strerror(dwSystemError);
        if(pszSystemError)
        {
            dwError = PMDAllocateString(pszSystemError, &pszError);
            BAIL_ON_CLI_ERROR(dwError);
        }
    }
    *ppszError = pszError;
cleanup:
    return dwError;
error:
    PMD_SAFE_FREE_MEMORY(pszError);
    goto cleanup;
}
