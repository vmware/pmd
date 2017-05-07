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
fwmgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PFWMGMT_CMD_ARGS pCmdArgs = NULL;
    FWMGMT_CLI_CMD_MAP arCmdMap[] =
    {
        {"restore",     fwmgmt_cli_restore_cmd},
        {"rules",       fwmgmt_cli_rules_cmd},
        {"version",     fwmgmt_cli_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(FWMGMT_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    dwError = fwmgmt_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        fwmgmt_cli_show_help();
    }
    else if(pCmdArgs->nCmdCount > 0)
    {
        pszCmd = pCmdArgs->ppszCmds[0];
        while(nCommandCount > 0)
        {
            --nCommandCount;
            if(!strcmp(pszCmd, arCmdMap[nCommandCount].pszCmdName))
            {
                nFound = 1;

                dwError = rpc_open(
                              "fwmgmt",
                              pMainArgs->pszServer,
                              pMainArgs->pszUser,
                              pMainArgs->pszDomain,
                              pMainArgs->pszPass,
                              pMainArgs->pszSpn,
                              &hPMD);
                BAIL_ON_CLI_ERROR(dwError);

                dwError = arCmdMap[nCommandCount].pFnCmd(hPMD, pCmdArgs);
                BAIL_ON_CLI_ERROR(dwError);
                break;
            }
        };
        if(!nFound)
        {
            show_no_such_cmd(pszCmd);
        }
    }
    else
    {
        fwmgmt_cli_show_help();
    }

cleanup:
    if(hPMD)
    {
        PMDFreeHandle(hPMD);
    }
    if(pCmdArgs)
    {
        fwmgmt_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = fwmgmt_get_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}

uint32_t
fwmgmt_cli_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    switch(pCmdArgs->nOperation)
    {
        case FWMGMT_OPERATION_LIST:
            dwError = fwmgmt_cli_get_rules_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case FWMGMT_OPERATION_SET:
            dwError = fwmgmt_cli_add_rules_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case FWMGMT_OPERATION_DELETE:
            dwError = fwmgmt_cli_delete_rules_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        default:
            fprintf(stderr,
                    "Invalid operation.\
                     Specify --list(default)|--set|--delete\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_CLI_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_cli_get_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_RULE pRules = NULL;
    PPMD_FIREWALL_RULE pRule = NULL;

    dwError = fwmgmt_get_rules(hPMD, pCmdArgs->nIPV6, &pRules);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "Persistent firewall rules:\n\n");
    for(pRule = pRules; pRule; pRule = pRule->pNext)
    {
        fprintf(stdout, "%s\n", pRule->pszRule);
    }

cleanup:
    fwmgmt_free_rules(pRules);
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_cli_add_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pCmdArgs->pszChain))
    {
        fprintf(stderr, "add requires a chain name. please specify with --chain <name>\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pCmdArgs->pszOpArgs))
    {
        fprintf(stderr, "add requires a ruleset. please specify with --add <ruleset>\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = fwmgmt_add_rule(
                  hPMD,
                  pCmdArgs->nIPV6,
                  pCmdArgs->nPersist,
                  pCmdArgs->pszChain,
                  pCmdArgs->pszOpArgs);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_cli_delete_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    int nPersist = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pCmdArgs->pszChain))
    {
        fprintf(stderr, "delete requires a chain name. please specify with --chain <name>\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(IsNullOrEmptyString(pCmdArgs->pszOpArgs))
    {
        fprintf(stderr, "delete requires a ruleset. please specify with --delete <ruleset>\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = fwmgmt_delete_rule(
                  hPMD,
                  pCmdArgs->nIPV6,
                  pCmdArgs->nPersist,
                  pCmdArgs->pszChain,
                  pCmdArgs->pszOpArgs);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_cli_restore_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_TABLE pTable = NULL;
    PPMD_FIREWALL_TABLE pTemp = NULL;
    PPMD_FIREWALL_CMD pCmd = NULL;
    PPMD_FIREWALL_CMD pTempCmd = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    //nat
    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_TABLE), (void **)&pTable);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateString("nat", &pTable->pszName);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_CMD), (void **)&pCmd);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateString("-P PREROUTING ACCEPT", &pCmd->pszRawCmd);
    BAIL_ON_CLI_ERROR(dwError);

    pTable->pCmds = pCmd;
    pCmd = NULL;

    //filter
    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_TABLE), (void **)&pTemp);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateString("filter", &pTemp->pszName);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_CMD), (void **)&pCmd);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateString("-P INPUT DROP", &pCmd->pszRawCmd);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_CMD), (void **)&pTempCmd);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = PMDAllocateString("-P INPUT DROP", &pTempCmd->pszRawCmd);
    BAIL_ON_CLI_ERROR(dwError);

    pCmd->pNext = pTempCmd;
    pTempCmd = NULL;

    pTemp->pCmds = pCmd;
    pCmd = NULL;

    pTable->pNext = pTemp;
    pTemp = NULL;

    dwError = fwmgmt_restore(hPMD, pCmdArgs->nIPV6, pTable);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    fwmgmt_free_cmd(pCmd);
    fwmgmt_free_table(pTemp);
    fwmgmt_free_table(pTable);
    return dwError;

error:
    goto cleanup;
}
