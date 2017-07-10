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

static GPOMGMT_CMD_ARGS _opt = {0};

//TODO: Modify the options later for group management
static struct option pstOptions[] =
{
    {OPT_SERVERNAME,  required_argument, 0, 0},//--server
    {OPT_USERNAME,    required_argument, 0, 0},//--user
    {OPT_DOMAINNAME,  required_argument, 0, 0},//--domain
    {OPT_PASSWORD,    required_argument, 0, 0},//--pass
    {OPT_SPN,         required_argument, 0, 0},//--spn
    {"6",             no_argument, 0, 0},
    {"add",           required_argument, 0, 0},
    {"chain",         required_argument, 0, 0},
    {"delete",        required_argument, 0, 0},
    {"help",          no_argument, 0, 'h'},                //-h --help
    {"list",          no_argument, 0, 0},
    {"persist",       no_argument, 0, 0},
    {"version",       no_argument, &_opt.nShowVersion, 1}, //--version
    {0, 0, 0, 0}
};

uint32_t
gpomgmt_parse_args(
    int argc,
    char* const* argv,
    GPOMGMT_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t dwError = 0;
    GPOMGMT_CMD_ARGS pCmdArgs = NULL;
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

    dwError = PMDAllocateMemory(sizeof(GPOMGMT_CMD_ARGS),
                               (void**)&pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    //pCmdArgs->nOperation = FWMGMT_OPERATION_LIST;//default to get

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
                   /* dwError = fwmgmt_parse_option(
                                  pstOptions[nOptionIndex].name,
                                  optarg,
                                  pCmdArgs);
                    BAIL_ON_CLI_ERROR(dwError); 
                    */
                break;
                case 'h':
                    _opt.nShowHelp = 1;
                break;
                case 'v':
                    _opt.nShowVersion=1;
                break;
                
                /*
                case '?':
                    dwError = fwmgmt_options_error(
                                  argv[optind-1],
                                  optarg);
                    BAIL_ON_CLI_ERROR(dwError);
                break;
                */
            }
    }

    pCmdArgs->nShowHelp = _opt.nShowHelp;
    pCmdArgs->nShowVersion = _opt.nShowVersion;
/*
    dwError = collect_extra_args(
                                 optind+1,//Move index up to start after component id
                                 argc,
                                 argv,
                                 &pCmdArgs->ppszCmds,
                                 &pCmdArgs->nCmdCount);
    BAIL_ON_CLI_ERROR(dwError);
*/
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
        gpomgmt_free_cmd_args(pCmdArgs);
    }
    goto cleanup;
}

uint32_t
fwmgmt_validate_options(
    const char *pszName,
    const char *pszArg,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!pszName || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

/*
uint32_t
fwmgmt_options_error(
    const char *pszName,
    const char *pszArg
    )
{
    uint32_t dwError = 0;

    if(!pszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if((!strcmp(pszName, "--add") ||
        !strcmp(pszName, "--delete") ||
        !strcmp(pszName, "--chain"))
       && IsNullOrEmptyString(pszArg))
    {
        fprintf(stderr, "Option %s requires an argument\n", pszName);

        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
fwmgmt_parse_option(
    const char* pszName,
    const char* pszArg,
    PFWMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!pszName || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = fwmgmt_validate_options(pszName, pszArg, pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(!strcasecmp(pszName, "list"))
    {
        pCmdArgs->nOperation = FWMGMT_OPERATION_LIST;
    }
    else if(!strcasecmp(pszName, "add"))
    {
        pCmdArgs->nOperation = FWMGMT_OPERATION_SET;

        dwError = PMDAllocateString(pszArg, &pCmdArgs->pszOpArgs);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(!strcasecmp(pszName, "delete"))
    {
        pCmdArgs->nOperation = FWMGMT_OPERATION_DELETE;

        dwError = PMDAllocateString(pszArg, &pCmdArgs->pszOpArgs);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(!strcasecmp(pszName, "persist"))
    {
        pCmdArgs->nPersist = 1;
    }
    else if(!strcasecmp(pszName, "chain"))
    {
        dwError = PMDAllocateString(pszArg, &pCmdArgs->pszChain);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(!strcasecmp(pszName, "6"))
    {
        pCmdArgs->nIPV6 = 1;
    }
cleanup:
    return dwError;

error:
    goto cleanup;
}
*/
void
gpomgmt_free_cmd_args(
    GPOWMGMT_CMD_ARGS pCmdArgs
    )
{
    //TODO:
    /*
    if(pCmdArgs)
    {
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszChain);
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszOpArgs);
        PMDFreeStringArrayWithCount(pCmdArgs->ppszCmds, pCmdArgs->nCmdCount);
        PMD_SAFE_FREE_MEMORY(pCmdArgs);
    }
    */
}
