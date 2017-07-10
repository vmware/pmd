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
       //  Add the other commands later,  
       // {"restore",     fwmgmt_cli_restore_cmd},
       // {"rules",       fwmgmt_cli_rules_cmd},
        {"version",     fwmgmt_cli_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(GPOMGMT_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;
    
    //TODO:
    dwError = gpomgmt_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        gpomgmt_cli_show_help();
    } else if (pCmdArgs->nShowVersion)
    {
        gpomgmt_cli_show_version_cmd();
    }/*
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
    } */
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
        //TODO:
        gpomgmt_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
gpomgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs) 
{

    //TODO: Implement the rpc later
    
    /*dwError = gpomgmt_get_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);
    */
    //fprintf(stdout, "version: %s\n", pszVersion);
    fprintf(stdout, "version: is being printed!! \n");

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}
