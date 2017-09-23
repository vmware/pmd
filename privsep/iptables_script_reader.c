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
read_iptables_script_file(
    const char *pszFile,
    PIPTABLES_SCRIPT_DATA *ppData
    )
{
    uint32_t dwError = 0;
    FILE *fp = NULL;
    char pszLine[MAX_SCRIPT_LINE_LENGTH] = {0};
    PIPTABLES_SCRIPT_DATA pData = NULL;
    PIPTABLES_SCRIPT_LINE pLine = NULL;
    PIPTABLES_SCRIPT_LINE pCurLine = NULL;

    if(IsNullOrEmptyString(pszFile) || !ppData)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fp = fopen(pszFile, "r");
    if(!fp)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(IPTABLES_SCRIPT_DATA),
                  (void **)&pData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszFile, &pData->pszFileName);
    BAIL_ON_PMD_ERROR(dwError);

    while(!feof(fp))
    {
        if(fgets(pszLine, MAX_SCRIPT_LINE_LENGTH, fp))
        {
            const char *pszTrimmedLine = ltrim(pszLine);

            dwError = process_script_line(pszTrimmedLine, &pLine);
            BAIL_ON_PMD_ERROR(dwError);

            if(!pData->pLines)
            {
                pData->pLines = pLine;
            }
            else if(pCurLine)
            {
                pCurLine->pNext = pLine;
                pLine->pPrev = pCurLine;
            }
            pCurLine = pLine;
            pLine = NULL;
        }
    }

    pCurLine = NULL;
    *ppData = pData;

cleanup:
    if(fp)
    {
        fclose(fp);
    }
    return dwError;

error:
    if(ppData)
    {
        *ppData = NULL;
    }
    free_iptables_script_line(pLine);
    free_iptables_script_data(pData);
    goto cleanup;
}

uint32_t
process_script_line(
    const char *pszInputLine,
    PIPTABLES_SCRIPT_LINE *ppLine
    )
{
    uint32_t dwError = 0;
    PIPTABLES_SCRIPT_LINE pLine = NULL;
    if(!pszInputLine || !ppLine)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(IPTABLES_SCRIPT_LINE), (void **)&pLine);
    BAIL_ON_PMD_ERROR(dwError);

    if(IsNullOrEmptyString(pszInputLine))
    {
        pLine->nType = SCRIPT_LINE_EMPTY;
    }
    else if(*pszInputLine == '#')
    {
        pLine->nType = SCRIPT_LINE_COMMENT;

        dwError = PMDAllocateString(pszInputLine, &pLine->pszComment);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(strstr(pszInputLine, IPTABLES_CMD) == pszInputLine)
    {
        pLine->nType = SCRIPT_LINE_RULE;

        dwError = PMDAllocateMemory(sizeof(IPTABLES_RULE),
                                    (void **)&pLine->pRule);
        BAIL_ON_PMD_ERROR(dwError);

        pLine->pRule->nAction = RULE_ACTION_KEEP;
        dwError = PMDAllocateString(pszInputLine, &pLine->pRule->pszOriginal);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        pLine->nType = SCRIPT_LINE_UNKNOWN;

        dwError = PMDAllocateString(pszInputLine, &pLine->pszUnknown);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppLine = pLine;

cleanup:
    return dwError;

error:
    if(ppLine)
    {
        *ppLine = NULL;
    }
    free_iptables_script_line(pLine);
    goto cleanup;
}

uint32_t
write_iptables_script_file(
    const char *pszFile,
    PIPTABLES_SCRIPT_DATA pData
    )
{
    uint32_t dwError = 0;
    FILE *fp = NULL;
    PIPTABLES_SCRIPT_LINE pLine = NULL;

    if(IsNullOrEmptyString(pszFile) || !pData)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fp = fopen(pszFile, "w");
    if(!fp)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pLine = pData->pLines; pLine; pLine = pLine->pNext)
    {
        switch(pLine->nType)
        {
            case SCRIPT_LINE_EMPTY:
                fprintf(fp, "\n");
                break;
            case SCRIPT_LINE_COMMENT:
                fprintf(fp, pLine->pszComment);
                break;
            case SCRIPT_LINE_UNKNOWN:
                fprintf(fp, pLine->pszUnknown);
                break;
            case SCRIPT_LINE_RULE:
                fprintf(fp, pLine->pRule->pszOriginal);
                break;
        }
    }

cleanup:
    if(fp)
    {
        fclose(fp);
    }
    return dwError;

error:
    goto cleanup;
}

void
free_iptables_script_rule(
    PIPTABLES_RULE pRule
    )
{
    if(!pRule)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pRule->pszOriginal);
    PMD_SAFE_FREE_MEMORY(pRule->pszNew);
    PMD_SAFE_FREE_MEMORY(pRule);
}

void
free_iptables_script_line(
    PIPTABLES_SCRIPT_LINE pLine
    )
{
    if(!pLine)
    {
        return;
    }
    while(pLine)
    {
        PIPTABLES_SCRIPT_LINE pTemp = pLine;
        switch(pLine->nType)
        {
            case SCRIPT_LINE_COMMENT:
                PMD_SAFE_FREE_MEMORY(pLine->pszComment);
                break;
            case SCRIPT_LINE_UNKNOWN:
                PMD_SAFE_FREE_MEMORY(pLine->pszUnknown);
                break;
            case SCRIPT_LINE_RULE:
                free_iptables_script_rule(pLine->pRule);
                break;
            default:
                break;
        }
        pLine = pTemp->pNext;
        PMD_SAFE_FREE_MEMORY(pTemp);
    }
}

void
free_iptables_script_data(
    PIPTABLES_SCRIPT_DATA pData
    )
{
    if(!pData)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pData->pszFileName);
    free_iptables_script_line(pData->pLines);
    PMD_SAFE_FREE_MEMORY(pData);
}

void
free_parse_context(
    PPARSE_CONTEXT pContext
    )
{
    if(pContext)
    {
        PMD_SAFE_FREE_MEMORY(pContext->pszCmd);
        fwmgmt_free_params(pContext->pParams);
        PMD_SAFE_FREE_MEMORY(pContext);
    }
}
