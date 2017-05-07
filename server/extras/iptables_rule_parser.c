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
params_make_param(
    const char *pszFlag,
    const char *pszValue,
    PPMD_FIREWALL_PARAM *ppParam
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_PARAM pParam = NULL;
    char *pszFlagEnd = NULL;
    char *pszValueEnd = NULL;
    char *pszFlagTrimmed = NULL;
    char *pszValueTrimmed = NULL;
    int nLength = 0;

    if((IsNullOrEmptyString(pszFlag) && IsNullOrEmptyString(pszValue)) ||
       !ppParam)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }


    dwError = PMDAllocateMemory(sizeof(PARAM), (void **)&pParam);
    BAIL_ON_PMD_ERROR(dwError);

    if(!IsNullOrEmptyString(pszFlag))
    {
        pParam->nFlag = 1;

        dwError = do_rtrim(pszFlag, &pParam->pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszValue))
    {
        dwError = do_rtrim(pszValue, &pParam->pszValue);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppParam = pParam;
cleanup:
    return dwError;

error:
    if(ppParam)
    {
        *ppParam = NULL;
    }
    fwmgmt_free_params(pParam);
    
    goto cleanup;
}

uint32_t
params_make_value(
    const char *pszValue,
    PPMD_FIREWALL_PARAM *ppParam
    )
{
    return params_make_param(NULL, pszValue, ppParam);
}

uint32_t
params_make_flag(
    const char *pszArg,
    PPMD_FIREWALL_PARAM *ppParam
    )
{
    return params_make_param(pszArg, NULL, ppParam);
}

uint32_t
params_parse_cb(
    const char *pszArg,
    PPARSE_CONTEXT pContext
    )
{
    uint32_t dwError = 0;
    int nFlag = 0;
    PPMD_FIREWALL_PARAM pParam = NULL;
    PPMD_FIREWALL_PARAM pParamLast = NULL;
    if(IsNullOrEmptyString(pszArg))
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pParamLast = pContext->pParams;
    while(pParamLast && pParamLast->pNext) pParamLast = pParamLast->pNext;

    dwError = param_is_flag(pszArg, &nFlag);
    BAIL_ON_PMD_ERROR(dwError);

    if(pContext->parseState == PARSE_STATE_BEGIN)
    {
        dwError = PMDAllocateString(pszArg, &pContext->pszCmd);
        BAIL_ON_PMD_ERROR(dwError);

        pContext->parseState = PARSE_STATE_READY;
    }
    else if(pContext->parseState == PARSE_STATE_READY)
    {
        if(nFlag)
        {
            pContext->parseState = PARSE_STATE_FLAG;

            dwError = params_make_flag(pszArg, &pParam);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else
        { 
            dwError = params_make_value(pszArg, &pParam);
            BAIL_ON_PMD_ERROR(dwError);
        }

        if(pParamLast)
        {
            pParamLast->pNext = pParam;
        }
        else
        {
            pContext->pParams = pParam;
        }
    }
    else if(pContext->parseState == PARSE_STATE_FLAG)
    {
        if(nFlag)
        {
            dwError = params_make_flag(pszArg, &pParam);
            BAIL_ON_PMD_ERROR(dwError);

            if(pParamLast)
            {
                pParamLast->pNext = pParam;
            }
            else
            {
                pContext->pParams = pParam;
            }
            pContext->parseState = PARSE_STATE_FLAG;
        }
        else
        {
            dwError = PMDAllocateString(pszArg, &pParamLast->pszValue);
            BAIL_ON_PMD_ERROR(dwError);

            pContext->parseState = PARSE_STATE_READY;
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
params_get_bounded(
    char chBoundary,
    const char *pszStart,
    int *pnLength
    )
{
    uint32_t dwError = 0;
    int nLength = 0;
    char *pszEnd = NULL;
    if(IsNullOrEmptyString(pszStart) || !pnLength)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszEnd = strchr(pszStart + 1, chBoundary);
    if(IsNullOrEmptyString(pszEnd))
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }
    nLength = (pszEnd - pszStart) + 1;
    *pnLength = nLength;

cleanup:
    return dwError;
error:
    if(pnLength)
    {
        *pnLength = 0;
    }
    goto cleanup;
}

uint32_t
params_invoke_cb(
    const char *pszStart,
    int nLength,
    PPARSE_CONTEXT pContext
    )
{
    uint32_t dwError = 0;
    char *pszArg = NULL;

    if(IsNullOrEmptyString(pszStart) || nLength < 0 || !pContext)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(nLength + 1, (void **)&pszArg);
    BAIL_ON_PMD_ERROR(dwError);

    strncpy(pszArg, pszStart, nLength);

    dwError = params_parse_cb(pszArg, pContext);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszArg);
    return dwError;

error:
    goto cleanup;
}

uint32_t
params_parse_string(
    const char *pszString,
    PPARSE_CONTEXT pContext
    )
{
    uint32_t dwError = 0;
    char chSep = ' ';
    int nIndex = 0;
    char *pszBoundary = NULL;
    const char *pszStart = NULL;

    if(IsNullOrEmptyString(pszString))
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszStart = pszString;
    while(1)
    {
        char *pszArg = NULL;
        int nLength = 0;
        pszBoundary = strchr(pszStart, chSep);

        if(!pszBoundary || pszBoundary <= pszStart)
        {
            break;
        }

        dwError = params_invoke_cb(pszStart, pszBoundary - pszStart, pContext);
        BAIL_ON_PMD_ERROR(dwError);

        while(*pszBoundary)
        {
            if(isspace(*pszBoundary))
            {
                ++pszBoundary;
            }
            else if(*pszBoundary == '"')
            {
                dwError = params_get_bounded('"', pszBoundary, &nLength);
                BAIL_ON_PMD_ERROR(dwError);

                dwError = params_invoke_cb(pszBoundary, nLength, pContext);
                BAIL_ON_PMD_ERROR(dwError);

                pszBoundary += nLength;
            }
            else
            {
                break;
            }
        }
        if(IsNullOrEmptyString(pszBoundary))
        {
            pszStart = NULL;
            break;
        }
        nIndex = pszBoundary - pszStart;
        pszStart += nIndex;
    }

    if(!IsNullOrEmptyString(pszStart))
    {
        params_parse_cb(pszStart, pContext);
    }

cleanup:
    return dwError = 0;

error:
    goto cleanup;
}

uint32_t
param_is_flag(
    const char *pszArg,
    int *pnFlag
    )
{
    uint32_t dwError = 0;
    int nFlag = 0;
    int nLen = 0;
    char *pszStart = NULL;
    const char FLAG = '-';

    if(IsNullOrEmptyString(pszArg) || !pnFlag)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nLen = strlen(pszArg);
    if(nLen < 2)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszArg[0] == FLAG)
    {
        int i = 1;
        if(pszArg[1] == FLAG)
        {
            i++;
        }
        if(isalnum(pszArg[i]))
        {
            nFlag = 1;
        }
    }

    *pnFlag = nFlag;

cleanup:
    return dwError;

error:
    if(dwError == ENOENT)
    {
        dwError = 0;
    }
    if(pnFlag)
    {
        *pnFlag = 0;
    }
    goto cleanup;
}
