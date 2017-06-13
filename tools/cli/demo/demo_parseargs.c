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

static DEMO_CMD_ARGS _opt = {0};

static struct option pstOptions[] =
{
    {OPT_SERVERNAME,  required_argument, 0, 0},//--server
    {OPT_USERNAME,    required_argument, 0, 0},//--user
    {OPT_DOMAINNAME,  required_argument, 0, 0},//--domain
    {OPT_PASSWORD,    required_argument, 0, 0},//--pass
    {OPT_SPN,         required_argument, 0, 0},//--spn
    {"help",          no_argument, 0, 'h'},                //-h --help
    {"version",       no_argument, &_opt.nShowVersion, 1}, //--version
    {0, 0, 0, 0}
};

uint32_t
demo_parse_args(
    int argc,
    char* const* argv,
    PDEMO_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t dwError = 0;
    PDEMO_CMD_ARGS pCmdArgs = NULL;
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

    dwError = PMDAllocateMemory(sizeof(DEMO_CMD_ARGS),
                               (void**)&pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    opterr = 0;//tell getopt to not print errors
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
                
            switch (nOption)
            {
                case 0:
                break;
                case 'h':
                    _opt.nShowHelp = 1;
                break;
                case '?':
                //ignore unknown options
                break;
            }
    }

    pCmdArgs->nShowHelp = _opt.nShowHelp;
    pCmdArgs->nShowVersion = _opt.nShowVersion;

    dwError = collect_extra_args(
                                 optind+1,//Move index up to start after component id
                                 argc,
                                 argv,
                                 &pCmdArgs->ppszCmds,
                                 &pCmdArgs->nCmdCount);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nCmdCount > 0 && !strcmp(pCmdArgs->ppszCmds[0], "help"))
    {
        pCmdArgs->nShowHelp = 1;
    }

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
        demo_free_cmd_args(pCmdArgs);
    }
    goto cleanup;
}

void
demo_free_cmd_args(
    PDEMO_CMD_ARGS pCmdArgs
    )
{
    if(pCmdArgs)
    {
        PMDFreeStringArrayWithCount(pCmdArgs->ppszCmds, pCmdArgs->nCmdCount);
        PMD_SAFE_FREE_MEMORY(pCmdArgs);
    }
}
