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

void
print_context(
    PPARSE_CONTEXT pContext
    )
{
    PPMD_FIREWALL_PARAM pParam = NULL;
    printf("Cmd = %s\n", pContext->pszCmd);
    for(pParam = pContext->pParams; pParam; pParam = pParam->pNext)
    {
        printf("Param = %s, Value = %s\n", pParam->pszName, pParam->pszValue);
    }
}

uint32_t
parse_iptables_rule(
    const char *pszRuleString,
    PPMD_FIREWALL_RULE *ppRule
    )
{
    uint32_t dwError = 0;
    PPARSE_CONTEXT pContext = NULL;
    PPMD_FIREWALL_RULE pRule = NULL;

    if(IsNullOrEmptyString(pszRuleString) || !ppRule)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PARSE_CONTEXT), (void **)&pContext);
    BAIL_ON_PMD_ERROR(dwError);

    pContext->parseState = PARSE_STATE_BEGIN;

    dwError = params_parse_string(pszRuleString, pContext);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_RULE), (void **)&pRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pContext->pszCmd, &pRule->pszCmd);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszRuleString, &pRule->pszRule);
    BAIL_ON_PMD_ERROR(dwError);

    pRule->pParams = pContext->pParams;
    pContext->pParams = NULL;

    *ppRule = pRule;
cleanup:
    free_parse_context(pContext);
    return dwError;

error:
    if(ppRule)
    {
        *ppRule = NULL;
    }
    fwmgmt_free_rules(pRule);
    goto cleanup;
}

uint32_t
get_restore_cmd(
    const char *pszCmd,
    char **ppszRestoreCmd
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_RULE pRule = NULL;
    PPMD_FIREWALL_PARAM pParam = NULL;
    char *pszRestoreCmd = NULL;

    if(IsNullOrEmptyString(pszCmd) || !ppszRestoreCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(strstr(pszCmd, "-P ") == pszCmd)
    {
        dwError = PMDAllocateStringPrintf(
                      &pszRestoreCmd,
                      ":%s [0:0]",
                      pszCmd+3);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(strstr(pszCmd, "-N ") == pszCmd)
    {
        dwError = PMDAllocateStringPrintf(
                      &pszRestoreCmd,
                      ":%s - [0:0]",
                      pszCmd+3);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = PMDAllocateString(pszCmd, &pszRestoreCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszRestoreCmd = pszRestoreCmd;
cleanup:
    fwmgmt_free_rules(pRule);
    return dwError;

error:
    if(ppszRestoreCmd)
    {
        *ppszRestoreCmd = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszRestoreCmd);
    goto cleanup;
}

uint32_t
get_firewall_rules(
    PIPTABLES_SCRIPT_DATA pData,
    PPMD_FIREWALL_RULE *ppFirewallRules
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_RULE pFirewallRules = NULL;
    PIPTABLES_SCRIPT_LINE pLine = NULL;
    PPMD_FIREWALL_RULE pRule = NULL;
    PPMD_FIREWALL_RULE pTail = NULL;

    if(!pData || !ppFirewallRules)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pLine = pData->pLines; pLine; pLine = pLine->pNext)
    {
        if(pLine->nType == SCRIPT_LINE_RULE)
        {
            dwError = parse_iptables_rule(pLine->pRule->pszOriginal, &pRule);
            BAIL_ON_PMD_ERROR(dwError);

            if(pTail == NULL)
            {
                pFirewallRules = pRule;
                pTail = pFirewallRules;
            }
            else
            {
                pTail->pNext = pRule;
                pTail = pTail->pNext;
            }
            pRule = NULL;
        }
    }

    *ppFirewallRules = pFirewallRules;

cleanup:
    return dwError;

error:
    if(ppFirewallRules)
    {
        *ppFirewallRules = NULL;
    }
    fwmgmt_free_rules(pRule);
    fwmgmt_free_rules(pFirewallRules);
    goto cleanup;
}

uint32_t
add_firewall_rule_to_script(
    const char *pszRule
    )
{
    uint32_t dwError = 0;
    PIPTABLES_SCRIPT_DATA pData = NULL;
    PIPTABLES_SCRIPT_LINE pLine = NULL;
    PIPTABLES_SCRIPT_LINE pNewLine = NULL;

    if(IsNullOrEmptyString(pszRule))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = read_iptables_script_file(IPTABLES_SCRIPT_PATH, &pData);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pData || !pData->pLines)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pLine = pData->pLines; pLine->pNext; pLine = pLine->pNext);

    dwError = PMDAllocateMemory(sizeof(IPTABLES_SCRIPT_LINE),
                                (void **)&pNewLine);
    BAIL_ON_PMD_ERROR(dwError);

    pNewLine->nType = SCRIPT_LINE_RULE;

    dwError = PMDAllocateMemory(sizeof(IPTABLES_RULE),
                                (void **)&pNewLine->pRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(
              &pNewLine->pRule->pszOriginal,
              "%s\n",
              pszRule);
    BAIL_ON_PMD_ERROR(dwError);

    pLine->pNext = pNewLine;

    pNewLine = NULL;

    dwError = write_iptables_script_file(IPTABLES_SCRIPT_PATH, pData);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    free_iptables_script_data(pData);
    return dwError;

error:
    free_iptables_script_line(pNewLine);
    goto cleanup;
}

uint32_t
delete_firewall_rule_from_script(
    const char *pszRule
    )
{
    uint32_t dwError = 0;
    PIPTABLES_SCRIPT_DATA pData = NULL;
    PIPTABLES_SCRIPT_LINE pLine = NULL;
    int nFound = 0;

    if(IsNullOrEmptyString(pszRule))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = read_iptables_script_file(IPTABLES_SCRIPT_PATH, &pData);
    BAIL_ON_PMD_ERROR(dwError);

    for(pLine = pData->pLines; pLine; pLine = pLine->pNext)
    {
        if(pLine->nType == SCRIPT_LINE_RULE)
        {
            PIPTABLES_RULE pRule = pLine->pRule;
            if(strstr(pRule->pszOriginal, pszRule))
            {
                PIPTABLES_SCRIPT_LINE pPrev = pLine->pPrev;
                if(!pPrev)
                {
                    pData->pLines = NULL;
                }
                else
                {
                    pPrev->pNext = pLine->pNext;
                }
                free_iptables_script_line(pLine);
                nFound = 1;
                break;
            }
        }
    }

    if(nFound)
    {
        dwError = write_iptables_script_file(IPTABLES_SCRIPT_PATH, pData);
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    free_iptables_script_data(pData);
    return dwError;

error:
    goto cleanup;
}
