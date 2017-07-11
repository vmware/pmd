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

static ROLEMGMT_CMD_ARGS _opt = {0};

static struct option pstOptions[] =
{
    {OPT_SERVERNAME,  required_argument, 0, 0},//--server
    {OPT_USERNAME,    required_argument, 0, 0},//--user
    {OPT_DOMAINNAME,  required_argument, 0, 0},//--domain
    {OPT_PASSWORD,    required_argument, 0, 0},//--pass
    {OPT_SPN,         required_argument, 0, 0},//--spn
    {"config",        required_argument, 0, 0},
    {"enable",        no_argument, 0, 0},
    {"update",        no_argument, 0, 0},
    {"remove",        no_argument, 0, 0},
    {"list",          no_argument, 0, 0},
    {"logs",          no_argument, 0, 0},
    {"prereqs",       no_argument, 0, 0},
    {"name",          required_argument, 0, 0},
    {"status",        no_argument, 0, 0},
    {"taskid",        required_argument, 0, 0},
    {"version",       no_argument, &_opt.nShowVersion, 1}, //--version
    {"help",          no_argument, &_opt.nShowHelp, 1},
    {0, 0, 0, 0}
};

uint32_t
rolemgmt_parse_args(
    int argc,
    char* const* argv,
    PROLEMGMT_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t dwError = 0;
    PROLEMGMT_CMD_ARGS pCmdArgs = NULL;
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

    dwError = PMDAllocateMemory(sizeof(ROLEMGMT_CMD_ARGS),
                               (void**)&pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    pCmdArgs->nOperation = ROLEMGMT_OPERATION_LIST;//default to get

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
                    dwError = rolemgmt_parse_option(
                                  pstOptions[nOptionIndex].name,
                                  optarg,
                                  pCmdArgs);
                    BAIL_ON_CLI_ERROR(dwError);
                break;
                case 'h':
                    _opt.nShowHelp = 1;
                break;
                case '?':
                    dwError = rolemgmt_options_error(
                                  argv[optind-1],
                                  optarg);
                    BAIL_ON_CLI_ERROR(dwError);
                break;
            }
    }

    pCmdArgs->nShowHelp = _opt.nShowHelp;
    pCmdArgs->nShowVersion = _opt.nShowVersion;
    if(_opt.nShowVersion)
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_VERSION;
    }

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

    dwError = rolemgmt_validate_options(pCmdArgs);
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
        rolemgmt_free_cmd_args(pCmdArgs);
    }
    goto cleanup;
}

uint32_t
rolemgmt_validate_options(
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_VERSION &&
       IsNullOrEmptyString(pCmdArgs->pszRole))
    {
        fprintf(stderr,
                "Specify a role name with --name to do this operation\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_PREREQS)
    {
        if(IsNullOrEmptyString(pCmdArgs->pszRole))
        {
            fprintf(stderr,
                    "Specify a role name with --name to do this operation\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_ENABLE)
    {
        if(IsNullOrEmptyString(pCmdArgs->pszRole))
        {
            fprintf(stderr,
                    "Specify a role name with --name to do this operation\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        else if(IsNullOrEmptyString(pCmdArgs->pszConfigFile))
        {
            fprintf(stderr,
                    "Specify a config file name with --config to do this operation\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_REMOVE)
    {
        if(IsNullOrEmptyString(pCmdArgs->pszRole))
        {
            fprintf(stderr,
                    "Specify a role name with --name to do this operation\n");
            fprintf(stderr,
                    "--config might be required. Please refer to your role docs.\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_UPDATE)
    {
        if(IsNullOrEmptyString(pCmdArgs->pszRole))
        {
            fprintf(stderr,
                    "Specify a role name with --name to do this operation\n");
            fprintf(stderr,
                    "--config might be required. Please refer to your role docs.\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_STATUS)
    {
        if(IsNullOrEmptyString(pCmdArgs->pszRole))
        {
            fprintf(stderr,
                    "Specify a role name with --name to do this operation\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        else if(IsNullOrEmptyString(pCmdArgs->pszTaskUUID))
        {
            fprintf(stderr,
                    "Specify a task id with --taskid to do this operation\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(pCmdArgs->nOperation == ROLEMGMT_OPERATION_LOGS)
    {
        if(IsNullOrEmptyString(pCmdArgs->pszTaskUUID))
        {
            fprintf(stderr,
                    "Specify a task id with --taskid to do this operation\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
        }
        BAIL_ON_CLI_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_options_error(
    const char *pszName,
    const char *pszArg
    )
{
    uint32_t dwError = 0;
    int nNumOptions = 0;
    int nFound = 0;

    if(!pszName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    nNumOptions = sizeof(pstOptions) / sizeof(pstOptions[0]) - 1;
    while(nNumOptions)
    {
        --nNumOptions;
        if(pstOptions[nNumOptions].name &&
           !strcmp(pszName, pstOptions[nNumOptions].name))
        {
            nFound = 1;
            break;
        }
    }

    if(!nFound)
    {
        fprintf(stderr, "There is no such option: %s\n", pszName);
        dwError = ERROR_PMD_CLI_NO_SUCH_OPTION;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(!strcmp(pszName, "--name") &&
       IsNullOrEmptyString(pszArg))
    {
        fprintf(stderr, "Option %s requires an argument\n", pszName);

        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(!strcmp(pszName, "--config") &&
            IsNullOrEmptyString(pszArg))
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
rolemgmt_parse_option(
    const char* pszName,
    const char* pszArg,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!pszName || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(!strcasecmp(pszName, "list"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_LIST;
    }
    else if(!strcasecmp(pszName, "logs"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_LOGS;
    }
    else if(!strcasecmp(pszName, "version"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_VERSION;
    }
    else if(!strcasecmp(pszName, "name"))
    {
        dwError = PMDAllocateString(pszArg, &pCmdArgs->pszRole);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(!strcasecmp(pszName, "prereqs"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_PREREQS;
    }
    else if(!strcasecmp(pszName, "enable"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_ENABLE;
    }
    else if(!strcasecmp(pszName, "config"))
    {
        dwError = PMDAllocateString(pszArg, &pCmdArgs->pszConfigFile);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(!strcasecmp(pszName, "remove"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_REMOVE;
    }
    else if(!strcasecmp(pszName, "update"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_UPDATE;
    }
    else if(!strcasecmp(pszName, "status"))
    {
        pCmdArgs->nOperation = ROLEMGMT_OPERATION_STATUS;
    }
    else if(!strcasecmp(pszName, "taskid"))
    {
        dwError = PMDAllocateString(pszArg, &pCmdArgs->pszTaskUUID);
        BAIL_ON_CLI_ERROR(dwError);
    }
cleanup:
    return dwError;

error:
    goto cleanup;
}

void
rolemgmt_free_cmd_args(
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    if(pCmdArgs)
    {
        PMD_SAFE_FREE_MEMORY(pCmdArgs->pszRole);
        PMDFreeStringArrayWithCount(pCmdArgs->ppszCmds, pCmdArgs->nCmdCount);
        PMD_SAFE_FREE_MEMORY(pCmdArgs);
    }
}
