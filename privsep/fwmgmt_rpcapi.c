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

unsigned32
fwmgmt_privsep_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;
    wstring_t pwszVersion = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_get_version(&pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    if(IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pwszVersion);
    goto cleanup;
}

unsigned32
fwmgmt_privsep_rpc_get_rules(
    handle_t hBinding,
    unsigned32 nIPV6,
    PPMD_RPC_FIREWALL_RULE_ARRAY *ppRpcRuleArray
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_RULE pFirewallRule = NULL;
    PPMD_FIREWALL_RULE pRule = NULL;
    PPMD_RPC_FIREWALL_RULE_ARRAY pRpcRuleArray = NULL;
    PPMD_RPC_FIREWALL_RULE pRpcRules = NULL;
    uint32_t dwCount = 0;
    int i = 0;
    if(!hBinding || !ppRpcRuleArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_get_rules(nIPV6, &pFirewallRule);
    BAIL_ON_PMD_ERROR(dwError);

    for(pRule = pFirewallRule; pRule; pRule = pRule->pNext)
    {
        ++dwCount;
    }

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_FIREWALL_RULE_ARRAY),
                  (void **)&pRpcRuleArray);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcRuleArray->dwCount = dwCount;

    dwError = PMDRpcServerAllocateMemory(
                  sizeof(PMD_RPC_FIREWALL_RULE) * dwCount,
                  (void **)&pRpcRules);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0, pRule = pFirewallRule; pRule; pRule = pRule->pNext, ++i)
    {
        dwError = PMDRpcServerAllocateWFromA(
                      pRule->pszRule,
                      &pRpcRules[i].pwszRule);
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRpcRuleArray->pRules = pRpcRules;

    *ppRpcRuleArray = pRpcRuleArray;

cleanup:
    fwmgmt_free_rules(pFirewallRule);
    return dwError;

error:
    if(ppRpcRuleArray)
    {
        *ppRpcRuleArray = NULL;
    }
    PMDRpcServerFreeMemory(ppRpcRuleArray);
    goto cleanup;
}

unsigned32
fwmgmt_privsep_rpc_add_rule(
    handle_t hBinding,
    unsigned32 nIPV6,
    unsigned32 nPersist,
    wstring_t pwszChain,
    wstring_t pwszRuleSpec
    )
{
    uint32_t dwError = 0;
    char *pszChain = NULL;
    char *pszRuleSpec = NULL;

    if(!hBinding || !pwszChain || !pwszRuleSpec)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszChain, &pszChain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszRuleSpec, &pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_add_rules(nIPV6, nPersist, pszChain, pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszChain);
    PMD_SAFE_FREE_MEMORY(pszRuleSpec);
    return dwError;

error:
    goto cleanup;
}

unsigned32
fwmgmt_privsep_rpc_delete_rule(
    handle_t hBinding,
    unsigned32 nIPV6,
    unsigned32 nPersist,
    wstring_t pwszChain,
    wstring_t pwszRuleSpec
    )
{
    uint32_t dwError = 0;
    char *pszChain = NULL;
    char *pszRuleSpec = NULL;

    if(!hBinding || !pwszChain || !pwszRuleSpec)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszChain, &pszChain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszRuleSpec, &pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_delete_rules(nIPV6, nPersist, pszChain, pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszChain);
    PMD_SAFE_FREE_MEMORY(pszRuleSpec);
    return dwError;

error:
    goto cleanup;
}

uint32_t
make_cmds(
    PPMD_RPC_FIREWALL_CMD_ARRAY pRpcCmds,
    PPMD_FIREWALL_CMD *ppCmds
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_CMD pCmds = NULL;
    PPMD_FIREWALL_CMD pCmd = NULL;
    int i = 0;

    if(!pRpcCmds || !ppCmds)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < pRpcCmds->dwCount; ++i)
    {
        dwError = PMDAllocateMemory(
                      sizeof(PMD_FIREWALL_CMD),
                      (void **)&pCmd);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                      pRpcCmds->pCmds[i].pwszRawCmd,
                      &pCmd->pszRawCmd);
        BAIL_ON_PMD_ERROR(dwError);

        if(!pCmds)
        {
            pCmds = pCmd;
        }
        else
        {
            PPMD_FIREWALL_CMD pTemp = pCmds;
            while(pTemp && pTemp->pNext) pTemp = pTemp->pNext;
            pTemp->pNext = pCmd;
        }
        pCmd = NULL;
    }

    *ppCmds = pCmds;

cleanup:
    return dwError;

error:
    if(ppCmds)
    {
        *ppCmds = NULL;
    }
    fwmgmt_free_cmd(pCmd);
    fwmgmt_free_cmd(pCmds);
    goto cleanup;
}

uint32_t
make_tables(
    PPMD_RPC_FIREWALL_TABLE_ARRAY pRpcTables,
    PPMD_FIREWALL_TABLE *ppTables
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_TABLE pTables = NULL;
    PPMD_FIREWALL_TABLE pTable = NULL;
    int i = 0;

    if(!pRpcTables || !ppTables)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < pRpcTables->dwCount; ++i)
    {
        dwError = PMDAllocateMemory(
                      sizeof(PMD_FIREWALL_TABLE),
                      (void **)&pTable);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                      pRpcTables->pTables[i].pwszName,
                      &pTable->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = make_cmds(pRpcTables->pTables[i].pCmds, &pTable->pCmds);
        BAIL_ON_PMD_ERROR(dwError);

        if(!pTables)
        {
            pTables = pTable;
        }
        else
        {
            PPMD_FIREWALL_TABLE pTemp = pTables;
            while(pTemp && pTemp->pNext) pTemp = pTemp->pNext;
            pTemp->pNext = pTable;
        }
        pTable = NULL;
    }

    *ppTables = pTables;
cleanup:
    return dwError;

error:
    if(ppTables)
    {
        *ppTables = NULL;
    }
    fwmgmt_free_table(pTables);
    fwmgmt_free_table(pTable);
    goto cleanup;
}

unsigned32
fwmgmt_privsep_rpc_restore(
    handle_t hBinding,
    unsigned32 nIPV6,
    PPMD_RPC_FIREWALL_TABLE_ARRAY pRpcTables
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_TABLE pTables = NULL;

    if(!hBinding || !pRpcTables)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_tables(pRpcTables, &pTables);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_restore(nIPV6, pTables);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    fwmgmt_free_table(pTables);
    return dwError;

error:
    goto cleanup;
}
