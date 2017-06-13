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
fwmgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    wstring_t pwszVersion = NULL;

    if(!hHandle || !ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(fwmgmt_rpc_version(hHandle->hRpc, &pwszVersion), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(
                  pwszVersion,
                  &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    PMDRpcClientFreeStringW(pwszVersion);
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszVersion);
    goto cleanup;
}

uint32_t
fwmgmt_get_rules(
    PPMDHANDLE hHandle,
    int nIPV6,
    PPMD_FIREWALL_RULE *ppRules
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_FIREWALL_RULE_ARRAY pRuleArray = NULL;
    PPMD_FIREWALL_RULE pRules = NULL;
    PPMD_FIREWALL_RULE pRule = NULL;
    PPMD_FIREWALL_RULE pTail = NULL;
    uint32_t i = 0;

    if(!hHandle || !ppRules)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    DO_RPC(fwmgmt_rpc_get_rules(hHandle->hRpc, nIPV6, &pRuleArray), dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pRuleArray || !pRuleArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < pRuleArray->dwCount; ++i)
    {
        dwError = PMDAllocateMemory(
                      sizeof(PMD_FIREWALL_RULE),
                      (void **)&pRule);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                      pRuleArray->pRules[i].pwszRule,
                      &pRule->pszRule);
        BAIL_ON_PMD_ERROR(dwError);
        if(!pTail)
        {
            pRules = pRule;
            pTail = pRules;
        }
        else
        {
            pTail->pNext = pRule;
            pTail = pTail->pNext;
        }
        pRule = NULL;
    }

    *ppRules = pRules;
cleanup:
    return dwError;

error:
    if(ppRules)
    {
        *ppRules = NULL;
    }
    fwmgmt_free_rules(pRule);
    fwmgmt_free_rules(pRules);
    goto cleanup;
}

uint32_t
fwmgmt_add_rule(
    PPMDHANDLE hHandle,
    int nIPV6,
    int nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    )
{
    uint32_t dwError = 0;
    wstring_t pwszChain = NULL;
    wstring_t pwszRuleSpec = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszChain) ||
       IsNullOrEmptyString(pszRuleSpec))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszChain, &pwszChain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszRuleSpec, &pwszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(
        fwmgmt_rpc_add_rule(
            hHandle->hRpc,
            nIPV6,
            nPersist,
            pwszChain,
            pwszRuleSpec), dwError);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszChain);
    PMD_SAFE_FREE_MEMORY(pwszRuleSpec);
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_delete_rule(
    PPMDHANDLE hHandle,
    int nIPV6,
    int nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    )
{
    uint32_t dwError = 0;
    wstring_t pwszChain = NULL;
    wstring_t pwszRuleSpec = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszChain) ||
       IsNullOrEmptyString(pszRuleSpec))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszChain, &pwszChain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszRuleSpec, &pwszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(
        fwmgmt_rpc_delete_rule(
            hHandle->hRpc,
            nIPV6,
            nPersist,
            pwszChain,
            pwszRuleSpec), dwError);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pwszChain);
    PMD_SAFE_FREE_MEMORY(pwszRuleSpec);
    return dwError;

error:
    goto cleanup;
}

void
fwmgmt_free_rpc_cmd_array(
    PPMD_RPC_FIREWALL_CMD_ARRAY pArray
    )
{
    uint32_t dwIndex = 0;
    if(!pArray)
    {
        return;
    }
    for(dwIndex = 0; dwIndex < pArray->dwCount; ++dwIndex)
    {
        PMD_SAFE_FREE_MEMORY(pArray->pCmds[dwIndex].pwszRawCmd);
    }
    PMD_SAFE_FREE_MEMORY(pArray->pCmds);
    PMDFreeMemory(pArray);
}

void
fwmgmt_free_rpc_table_array(
    PPMD_RPC_FIREWALL_TABLE_ARRAY pArray
    )
{
    uint32_t dwIndex = 0;
    if(!pArray)
    {
        return;
    }
    for(dwIndex = 0; dwIndex < pArray->dwCount; ++dwIndex)
    {
        fwmgmt_free_rpc_cmd_array(pArray->pTables[dwIndex].pCmds);
        PMD_SAFE_FREE_MEMORY(pArray->pTables[dwIndex].pwszName);
    }
    PMD_SAFE_FREE_MEMORY(pArray->pTables);
    PMDFreeMemory(pArray);
}

uint32_t
make_rpc_cmds(
    PPMD_FIREWALL_CMD pCmds,
    PPMD_RPC_FIREWALL_CMD_ARRAY *ppRpcCmds
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_CMD pTemp = NULL;
    PPMD_RPC_FIREWALL_CMD_ARRAY pRpcCmds = NULL;
    int nCmdCount = 0;
    int i = 0;

    if(!pCmds || !ppRpcCmds)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_RPC_FIREWALL_CMD_ARRAY),
                                (void **)&pRpcCmds);
    BAIL_ON_PMD_ERROR(dwError);

    for(pTemp = pCmds; pTemp; pTemp = pTemp->pNext) ++nCmdCount;

    pRpcCmds->dwCount = nCmdCount;

    dwError = PMDAllocateMemory(
                  sizeof(PMD_RPC_FIREWALL_CMD) * nCmdCount,
                  (void **)&pRpcCmds->pCmds);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0, pTemp = pCmds; pTemp; pTemp = pTemp->pNext, ++i)
    {
        dwError = PMDAllocateStringWFromA(
                      pTemp->pszRawCmd,
                      &pRpcCmds->pCmds[i].pwszRawCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRpcCmds = pRpcCmds;

cleanup:
    return dwError;

error:
    if(ppRpcCmds)
    {
        *ppRpcCmds = NULL;
    }
    fwmgmt_free_rpc_cmd_array(pRpcCmds);
    goto cleanup;
}

uint32_t
make_rpc_tables(
    PPMD_FIREWALL_TABLE pTables,
    PPMD_RPC_FIREWALL_TABLE_ARRAY *ppRpcTables
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_TABLE pTemp = NULL;
    PPMD_RPC_FIREWALL_TABLE_ARRAY pRpcTables = NULL;
    int nTableCount = 0;
    int i = 0;

    if(!pTables || !ppRpcTables)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_RPC_FIREWALL_TABLE_ARRAY),
                                (void **)&pRpcTables);
    BAIL_ON_PMD_ERROR(dwError);

    for(pTemp = pTables; pTemp; pTemp = pTemp->pNext) ++nTableCount;

    pRpcTables->dwCount = nTableCount;

    dwError = PMDAllocateMemory(
                  sizeof(PMD_RPC_FIREWALL_TABLE) * nTableCount,
                  (void **)&pRpcTables->pTables);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0, pTemp = pTables; pTemp; pTemp = pTemp->pNext, ++i)
    {
        dwError = PMDAllocateStringWFromA(
                      pTemp->pszName,
                      &pRpcTables->pTables[i].pwszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = make_rpc_cmds(pTemp->pCmds, &pRpcTables->pTables[i].pCmds);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRpcTables = pRpcTables;

cleanup:
    return dwError;

error:
    if(ppRpcTables)
    {
        *ppRpcTables = NULL;
    }
    fwmgmt_free_rpc_table_array(pRpcTables);
    goto cleanup;
}

uint32_t
fwmgmt_restore(
    PPMDHANDLE hHandle,
    int nIPV6,
    PPMD_FIREWALL_TABLE pTable
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_FIREWALL_TABLE_ARRAY pRpcTables = NULL;

    if(!hHandle || !pTable)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = make_rpc_tables(pTable, &pRpcTables);
    BAIL_ON_PMD_ERROR(dwError);

    DO_RPC(fwmgmt_rpc_restore(hHandle->hRpc, nIPV6, pRpcTables), dwError);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    fwmgmt_free_rpc_table_array(pRpcTables);
    return dwError;

error:
    goto cleanup;
}
