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
rolemgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PROLEMGMT_CMD_ARGS pCmdArgs = NULL;
    ROLEMGMT_CLI_CMD_MAP arCmdMap[] =
    {
        {"roles",       rolemgmt_cli_roles_cmd},
        {"version",     rolemgmt_cli_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(ROLEMGMT_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    dwError = rolemgmt_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        rolemgmt_cli_show_help();
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
                              "rolemgmt",
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
        rolemgmt_cli_show_help();
    }

cleanup:
    if(hPMD)
    {
        PMDFreeHandle(hPMD);
    }
    if(pCmdArgs)
    {
        rolemgmt_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = rolemgmt_get_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_roles_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
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
        case ROLEMGMT_OPERATION_LIST:
            dwError = rolemgmt_cli_get_roles_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_SET:
            //dwError = fwmgmt_cli_add_rules_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_DELETE:
            //dwError = fwmgmt_cli_delete_rules_cmd(hPMD, pCmdArgs);
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
rolemgmt_cli_get_roles_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;

    dwError = rolemgmt_get_roles(hPMD, &pRoles);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "Available roles:\n\n");
    for(pRole = pRoles; pRole; pRole = pRole->pNext)
    {
        fprintf(stdout, "%s\n", pRole->pszRole);
    }

cleanup:
    rolemgmt_free_roles(pRoles);
    return dwError;

error:
    goto cleanup;
}
