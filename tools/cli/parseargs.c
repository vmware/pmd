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

static PMD_CMD_ARGS _main_opt = {0};

//options - 
static struct option _pstMainOptions[] =
{
    {OPT_SERVERNAME,        required_argument, 0, 0},//--servername
    {OPT_USERNAME,          required_argument, 0, 0},//--user
    {OPT_DOMAINNAME,        required_argument, 0, 0},//--domain
    {OPT_SPN,               required_argument, 0, 0},//--spn
    {0, 0, 0, 0}
};

uint32_t
parse_comp_cmd(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_CMD_ARGS pCmdArgs = NULL;
    int nOptionIndex = 0;
    int nOption = 0;

    if(!ppCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                            sizeof(PMD_CMD_ARGS),
                            (void**)&pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    opterr = 0;//tell getopt to not print errors
    while (1)
    {
                
        nOption = getopt_long (
                      argc,
                      argv,
                      "",
                      _pstMainOptions,
                      &nOptionIndex);
        if (nOption == -1)
            break;

        switch(nOption)
        {
            case 0:
                dwError = parse_option(
                              _pstMainOptions[nOptionIndex].name,
                              optarg,
                              pCmdArgs);
                BAIL_ON_CLI_ERROR(dwError);
            break;
            case '?':
                //Ignore unknown options as components might be handling
            break;
        }
    }

    dwError = collect_extra_args(
                                 optind,
                                 argc,
                                 argv,
                                 &pCmdArgs->ppszCmds,
                                 &pCmdArgs->nCmdCount);
    BAIL_ON_CLI_ERROR(dwError);

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
        free_cmd_args(pCmdArgs);
    }
    goto cleanup;
}

uint32_t
parse_option(
    const char* pszName,
    const char* pszArg,
    PPMD_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char **ppszOptArg = NULL;

    if(!pszName || !pCmdArgs)
    {
        dwError = ERROR_PMD_CLI_INVALID_ARGUMENT;
        BAIL_ON_CLI_ERROR(dwError);
    }
    if(!strcasecmp(pszName, OPT_SERVERNAME))
    {
        ppszOptArg = &pCmdArgs->pszServer;
    }
    else if(!strcasecmp(pszName, OPT_USERNAME))
    {
        ppszOptArg = &pCmdArgs->pszUser;
    }
    else if(!strcasecmp(pszName, OPT_DOMAINNAME))
    {
        ppszOptArg = &pCmdArgs->pszDomain;
    }
    else if(!strcasecmp(pszName, OPT_SPN))
    {
        ppszOptArg = &pCmdArgs->pszSpn;
    }

    if(ppszOptArg)
    {
        if(!optarg)
        {
            dwError = ERROR_PMD_CLI_OPTION_ARG_REQUIRED;
            BAIL_ON_CLI_ERROR(dwError);
        }
        dwError = PMDAllocateString(optarg, ppszOptArg);
        BAIL_ON_CLI_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}


uint32_t
collect_extra_args(
    int argIndex,
    int argc,
    char* const* argv,
    char*** pppszCmds,
    int* pnCmdCount
    )
{
    uint32_t dwError = 0;
    char** ppszCmds = NULL;
    int nCmdCount = 0;

    if(!argv || !pppszCmds || !pnCmdCount)
    {
        dwError = ERROR_PMD_CLI_INVALID_ARGUMENT;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (argIndex < argc)
    {
        int nIndex = 0;
        nCmdCount = argc - argIndex;
        dwError = PMDAllocateMemory(
                                nCmdCount * sizeof(char*),
                                (void**)&ppszCmds);
        BAIL_ON_CLI_ERROR(dwError);
        
        while (argIndex < argc)
        {
            dwError = PMDAllocateString(
                             argv[argIndex++],
                             &ppszCmds[nIndex++]);
            BAIL_ON_CLI_ERROR(dwError);
        }
    }

    *pppszCmds = ppszCmds;
    *pnCmdCount = nCmdCount;

cleanup:
    return dwError;

error:
    if(pppszCmds)
    {
        *pppszCmds = NULL;
    }
    if(pnCmdCount)
    {
        *pnCmdCount = 0;
    }
    PMDFreeStringArrayWithCount(ppszCmds, nCmdCount);
    goto cleanup;
}

void
free_cmd_args(
    PPMD_CMD_ARGS pCmdArgs
    )
{
    int nIndex = 0;
    if(pCmdArgs)
    {
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszServer);
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszUser);
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszDomain);
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszPass);
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszSpn);
        PMDFreeStringArrayWithCount(pCmdArgs->ppszCmds, pCmdArgs->nCmdCount);
    }
    PMD_SAFE_FREE_MEMORY(pCmdArgs);
}
