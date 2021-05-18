/*
 * Copyright © 2016-2021 VMware, Inc.  All Rights Reserved.
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

uint32_t
add_set_opt(
    PTDNF_CMD_ARGS pCmdArgs,
    const char* pszOptArg
    )
{
    uint32_t dwError = 0;
    PTDNF_CMD_OPT pCmdOpt = NULL;

    if (!pCmdArgs || IsNullOrEmptyString(pszOptArg))
    {
        dwError = ERROR_PMD_CLI_INVALID_OPTION;
        BAIL_ON_CLI_ERROR(dwError);
    }
    dwError = get_option_and_value(pszOptArg, &pCmdOpt);
    BAIL_ON_CLI_ERROR(dwError);

    if (!strcmp(pCmdOpt->pszOptName, "tdnf.conf"))
    {
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszConfFile);
        dwError = PMDSafeAllocateString(
                      pCmdOpt->pszOptValue,
                      &pCmdArgs->pszConfFile);
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = add_set_opt_with_values(pCmdArgs,
                            CMDOPT_KEYVALUE,
                            pCmdOpt->pszOptName,
                            pCmdOpt->pszOptValue);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    if (pCmdOpt)
    {
        pmd_free_pkg_cmd_opt(pCmdOpt);
    }
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pCmdArgs->pszConfFile);
    goto cleanup;
}

uint32_t
add_set_opt_with_values(
    PTDNF_CMD_ARGS pCmdArgs,
    int nType,
    const char *pszOptArg,
    const char *pszOptValue
    )
{
    uint32_t dwError = 0;
    PTDNF_CMD_OPT pCmdOpt = NULL;
    PTDNF_CMD_OPT pSetOptTemp = NULL;

    if (!pCmdArgs ||
       IsNullOrEmptyString(pszOptArg) ||
       IsNullOrEmptyString(pszOptValue) || nType == CMDOPT_CURL_INIT_CB)
    {
        dwError = ERROR_PMD_CLI_INVALID_OPTION;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(TDNF_CMD_OPT), (void **)&pCmdOpt);
    BAIL_ON_CLI_ERROR(dwError);

    pCmdOpt->nType = nType;

    dwError = PMDSafeAllocateString(pszOptArg, &pCmdOpt->pszOptName);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDSafeAllocateString(pszOptValue, &pCmdOpt->pszOptValue);
    BAIL_ON_CLI_ERROR(dwError);

    pSetOptTemp = pCmdArgs->pSetOpt;
    if (pSetOptTemp)
    {
        while (pSetOptTemp->pNext)
        {
            pSetOptTemp = pSetOptTemp->pNext;
        }
        pSetOptTemp->pNext = pCmdOpt;
    }
    else
    {
        pCmdArgs->pSetOpt = pCmdOpt;
    }

cleanup:
    return dwError;

error:
    if (pCmdOpt)
    {
        pmd_free_pkg_cmd_opt(pCmdOpt);
    }
    goto cleanup;
}

uint32_t
get_option_and_value(
    const char* pszOptArg,
    PTDNF_CMD_OPT* ppCmdOpt
    )
{
    uint32_t dwError = 0;
    const char* EQUAL_SIGN = "=";
    const char* pszIndex = NULL;
    PTDNF_CMD_OPT pCmdOpt = NULL;
    int nEqualsPos = -1;

    if (IsNullOrEmptyString(pszOptArg) || !ppCmdOpt)
    {
        dwError = ERROR_PMD_CLI_INVALID_OPTION;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszIndex = strstr(pszOptArg, EQUAL_SIGN);
    if (!pszIndex)
    {
        dwError = ERROR_PMD_SETOPT_NO_EQUALS;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(TDNF_CMD_OPT), (void**)&pCmdOpt);
    BAIL_ON_CLI_ERROR(dwError);

    pCmdOpt->nType = CMDOPT_KEYVALUE;
    dwError = PMDSafeAllocateString(pszOptArg, &pCmdOpt->pszOptName);
    BAIL_ON_CLI_ERROR(dwError);

    nEqualsPos = pszIndex - pszOptArg;
    pCmdOpt->pszOptName[nEqualsPos] = '\0';

    pCmdOpt->nType = CMDOPT_KEYVALUE;
    dwError = PMDSafeAllocateString(pszOptArg+nEqualsPos+1,
                                 &pCmdOpt->pszOptValue);
    BAIL_ON_CLI_ERROR(dwError);

    *ppCmdOpt = pCmdOpt;

cleanup:
    return dwError;

error:
    if (ppCmdOpt)
    {
        *ppCmdOpt = NULL;
    }
    if (pCmdOpt)
    {
        pmd_free_pkg_cmd_opt(pCmdOpt);
    }
    goto cleanup;
}

void
pmd_free_pkg_cmd_opt(
    PTDNF_CMD_OPT pCmdOpt
    )
{
    PTDNF_CMD_OPT pCmdOptNext = NULL;
    while (pCmdOpt)
    {
        pCmdOptNext = pCmdOpt->pNext;

        PMD_SAFE_FREE_MEMORY(pCmdOpt->pszOptName);

        if (pCmdOpt->nType != CMDOPT_CURL_INIT_CB)
        {
            PMD_SAFE_FREE_MEMORY(pCmdOpt->pszOptValue);
        }
        else
        {
            pCmdOpt->pfnCurlConfigCB = NULL;
        }

        PMD_SAFE_FREE_MEMORY(pCmdOpt);
        pCmdOpt = pCmdOptNext;
    }
}

