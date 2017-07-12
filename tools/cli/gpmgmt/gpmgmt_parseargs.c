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

static gpMGMT_CMD_ARGS _opt = {0};

//TODO: Modify the options later for group management
static struct option pstOptions[] =
{
    {"help",          no_argument, &_opt.nShowHelp, 1},    // --help
    {"version",       no_argument, &_opt.nShowVersion, 1}, //--version
    {0, 0, 0, 0}
};

uint32_t
gpmgmt_parse_args(
    int argc,
    char* const* argv,
    PgpMGMT_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t dwError = 0;
    PgpMGMT_CMD_ARGS pCmdArgs = NULL;
    int nOptionIndex = 0;
    int nOption = 0;
    int nIndex = 0;
    //reset arg parse index for rescan
    optind = 1;

    if(!ppCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(gpMGMT_CMD_ARGS),
                               (void**)&pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    while (1)
    {
            nOption = getopt_long (
                           argc,
                           argv,
                           "hv",
                           pstOptions,
                           &nOptionIndex);
            if (nOption == -1)
                break;
    }

    pCmdArgs->nShowHelp = _opt.nShowHelp;
    pCmdArgs->nShowVersion = _opt.nShowVersion;
    //fprintf(stdout,"\nParsing the commandline arguments\n");
    //fprintf(stdout,"Helpflag = %d, Versionflag =%d \n",pCmdArgs->nShowHelp,pCmdArgs->nShowVersion);
    
    *ppCmdArgs = pCmdArgs;

cleanup:
    return dwError;

error:
    if(ppCmdArgs)
    {
        *ppCmdArgs = NULL;
    }
    if(pCmdArgs)
    {
        gpmgmt_free_cmd_args(pCmdArgs);
    }
    goto cleanup;
}

void
gpmgmt_free_cmd_args(
    PgpMGMT_CMD_ARGS pCmdArgs
    )
{
    if(pCmdArgs)
    {
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszChain);
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszOpArgs);
        PMDFreeStringArrayWithCount(pCmdArgs->ppszCmds, pCmdArgs->nCmdCount);
        PMD_SAFE_FREE_MEMORY(pCmdArgs);
    }
}
