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
fwmgmt_free_params(
    PPMD_FIREWALL_PARAM pParams
    )
{
    while(pParams)
    {
        PPMD_FIREWALL_PARAM pParam = pParams->pNext;
        PMD_SAFE_FREE_MEMORY(pParams->pszName);
        PMD_SAFE_FREE_MEMORY(pParams->pszValue);
        PMD_SAFE_FREE_MEMORY(pParams);
        pParams = pParam;
    }
}

void
fwmgmt_free_rules(
    PPMD_FIREWALL_RULE pRules
    )
{
    while(pRules)
    {
        PPMD_FIREWALL_RULE pRule = pRules->pNext;
        PMD_SAFE_FREE_MEMORY(pRules->pszRule);
        PMD_SAFE_FREE_MEMORY(pRules->pszCmd);
        fwmgmt_free_params(pRules->pParams);
        PMD_SAFE_FREE_MEMORY(pRules);
        pRules = pRule;
    }
}

void
fwmgmt_free_cmd(
    PPMD_FIREWALL_CMD pCmds
    )
{
    while(pCmds)
    {
        PPMD_FIREWALL_CMD pCmd = pCmds->pNext;
        PMD_SAFE_FREE_MEMORY(pCmds->pszRawCmd);
        PMD_SAFE_FREE_MEMORY(pCmds);
        pCmds = pCmd;
    }
}

void
fwmgmt_free_table(
    PPMD_FIREWALL_TABLE pTables
    )
{
    while(pTables)
    {
        PPMD_FIREWALL_TABLE pTable = pTables->pNext;
        PMD_SAFE_FREE_MEMORY(pTables->pszName);
        fwmgmt_free_cmd(pTables->pCmds);
        PMD_SAFE_FREE_MEMORY(pTables);
        pTables = pTable;
    }
}
