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
pkg_validate_option_name(
    const char* pszName,
    struct option* pKnownOptions
    )
{
    uint32_t dwError = 0;
    struct option* pOption = NULL;

    if(IsNullOrEmptyString(pszName) || !pKnownOptions)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = pkg_get_option_by_name(pszName, pKnownOptions, &pOption);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_validate_option_arg(
    const char* pszName,
    const char* pszArg,
    struct option* pKnownOptions
    )
{
    uint32_t dwError = 0;
    struct option* pOption = NULL;

    if(IsNullOrEmptyString(pszName) || !pKnownOptions)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = pkg_get_option_by_name(pszName, pKnownOptions, &pOption);
    BAIL_ON_CLI_ERROR(dwError);

    if(IsNullOrEmptyString(pszArg) && pOption->has_arg == required_argument)
    {
        dwError = ERROR_PMD_CLI_OPTION_ARG_REQUIRED;
    }

    if(!IsNullOrEmptyString(pszArg) && pOption->has_arg == no_argument)
    {
        dwError = ERROR_PMD_CLI_OPTION_ARG_UNEXPECTED;
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_validate_options(
    const char* pszName,
    const char* pszArg,
    struct option* pKnownOptions
    )
{
    uint32_t dwError = 0;

    //pszArg can be NULL
    if(IsNullOrEmptyString(pszName) ||
       !pKnownOptions)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = pkg_validate_option_name(pszName, pKnownOptions);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = pkg_validate_option_arg(pszName, pszArg, pKnownOptions);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_get_option_by_name(
    const char* pszName,
    struct option* pKnownOptions,
    struct option** ppOption
    )
{
    uint32_t dwError = 0;
    struct option* pOption = NULL;

    if(IsNullOrEmptyString(pszName) || !pKnownOptions || !ppOption)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    while(pKnownOptions->name)
    {
        if(!strcmp(pszName, pKnownOptions->name))
        {
            pOption = pKnownOptions;
            break;
        } 
        ++pKnownOptions;
    }
    if(!pOption)
    {
        dwError = ERROR_PMD_CLI_OPTION_NAME_INVALID;
        BAIL_ON_CLI_ERROR(dwError);
    }

    *ppOption = pOption;

cleanup:
    return dwError;

error:
    if(ppOption)
    {
        *ppOption = NULL;
    }
    goto cleanup;
}
