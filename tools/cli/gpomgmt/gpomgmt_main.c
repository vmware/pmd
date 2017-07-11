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
gpomgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PGPOMGMT_CMD_ARGS pCmdArgs = NULL;
    GPOMGMT_CLI_CMD_MAP arCmdMap[] =
    {
       //TODO:// Add the other commands later,  
       // {"restore",     fwmgmt_cli_restore_cmd},
       // {"rules",       fwmgmt_cli_rules_cmd},
        {"version",     gpomgmt_cli_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(GPOMGMT_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;
    
    dwError = gpomgmt_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        gpomgmt_cli_show_help();
    } else if (pCmdArgs->nShowVersion)
    {
        dwError = rpc_open(
            "gpomgmt",
            pMainArgs->pszServer,
            pMainArgs->pszUser,
            pMainArgs->pszDomain,
            pMainArgs->pszPass,
            pMainArgs->pszSpn,
            &hPMD);
        BAIL_ON_CLI_ERROR(dwError);
            fprintf(stdout,"\n Opened RPC connection\n");

        gpomgmt_cli_show_version_cmd(hPMD, pCmdArgs);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else
    {
        gpomgmt_cli_show_help();
    } 

cleanup:
    if(hPMD)
    {
        PMDFreeHandle(hPMD);
    }
    if(pCmdArgs)
    {
        gpomgmt_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
gpomgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PGPOMGMT_CMD_ARGS pCmdArgs
    )
{
    fprintf(stdout,"\n In the client: call gpomgmt_cli_show_version_cmd \n");
    uint32_t dwError = 0;
    char* pszVersion = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }
    
    fprintf(stdout,"\n No errors with respect to arguments\n");

    dwError = gpomgmt_get_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}