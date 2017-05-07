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

static TDNF_CMD_ARGS _opt = {0};

//options - incomplete
static struct option pstOptions[] =
{
    {OPT_SERVERNAME,  required_argument, 0, 0},//--server
    {OPT_USERNAME,    required_argument, 0, 0},//--user
    {OPT_DOMAINNAME,  required_argument, 0, 0},//--domain
    {OPT_PASSWORD,    required_argument, 0, 0},//--pass
    {OPT_SPN,         required_argument, 0, 0},//--spn
    {"allowerasing",  no_argument, &_opt.nAllowErasing, 1},//--allowerasing
    {"assumeno",      no_argument, &_opt.nAssumeNo, 1},    //--assumeno
    {"assumeyes",     no_argument, 0, 'y'},                //--assumeyes
    {"best",          no_argument, &_opt.nBest, 1},        //--best
    {"cacheonly",     no_argument, 0, 'C'},                //-C, --cacheonly
    {"config",        required_argument, 0, 'c'},          //-c, --config
    {"debuglevel",    required_argument, 0, 'd'},          //-d, --debuglevel
    {"debugsolver",   no_argument, &_opt.nDebugSolver, 1}, //--debugsolver
    {"disablerepo",   required_argument, 0, 0},            //--disablerepo
    {"enablerepo",    required_argument, 0, 0},            //--enablerepo
    {"errorlevel",    required_argument, 0, 'e'},          //-e --errorlevel
    {"help",          no_argument, 0, 'h'},                //-h --help
    {"nogpgcheck",    no_argument, &_opt.nNoGPGCheck, 1},  //--nogpgcheck
    {"refresh",       no_argument, &_opt.nRefresh, 1},     //--refresh 
    {"showduplicates",required_argument, 0, 0},            //--showduplicates
    {"version",       no_argument, &_opt.nShowVersion, 1}, //--version
    {"verbose",       no_argument, &_opt.nVerbose, 1},     //-v --verbose
    {"4",             no_argument, 0, '4'},                //-4 resolve to IPv4 addresses only
    {"6",             no_argument, 0, '6'},                //-4 resolve to IPv4 addresses only
    {0, 0, 0, 0}
};

uint32_t
pkg_parse_args(
    int argc,
    char* const* argv,
    PTDNF_CMD_ARGS* ppCmdArgs
    )
{
    uint32_t dwError = 0;
    PTDNF_CMD_ARGS pCmdArgs = NULL;
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

    dwError = PMDAllocateMemory(
                            sizeof(TDNF_CMD_ARGS),
                            (void**)&pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    opterr = 0;//tell getopt to not print errors
    while (1)
    {
                
            nOption = getopt_long (
                           argc,
                           argv,
                           "46bCc:d:e:hqvxy",
                           pstOptions,
                           &nOptionIndex);
            if (nOption == -1)
                break;
                
            switch (nOption)
            {
                case 0:
                    dwError = pkg_parse_option(
                                  pstOptions[nOptionIndex].name,
                                  optarg,
                                  pCmdArgs);
                    BAIL_ON_CLI_ERROR(dwError);
                break;
                case 'b':
                    _opt.nBest = 1;
                break;
                case 'e':
                break;
                case 'C':
                    _opt.nCacheOnly = 1;
                break;
                case 'h':
                    _opt.nShowHelp = 1;
                break;
                case 'r':
                break;
                case 'y':
                    _opt.nAssumeYes = 1;
                break;
                case '4':
                    _opt.nIPv4 = 1;
                break;
                case '6':
                    _opt.nIPv6 = 1;
                break;
                case '?':
                    dwError = pkg_handle_options_error(
                                  argv[optind-1],
                                  optarg,
                                  pstOptions);
                    BAIL_ON_CLI_ERROR(dwError);
                //TODO: Handle unknown option, incomplete options
                break;
            }
    }

    dwError = pkg_copy_options(&_opt, pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = collect_extra_args(
                                 optind+1,//Move index up to start after component id
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
        pkg_free_cmd_args(pCmdArgs);
    }
    goto cleanup;
}

uint32_t
pkg_copy_options(
    PTDNF_CMD_ARGS pOptionArgs,
    PTDNF_CMD_ARGS pArgs
    )
{
    uint32_t dwError = 0;
    if(!pOptionArgs || !pArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pArgs->nAllowErasing  = pOptionArgs->nAllowErasing;
    pArgs->nAssumeNo      = pOptionArgs->nAssumeNo;
    pArgs->nAssumeYes     = pOptionArgs->nAssumeYes;
    pArgs->nBest          = pOptionArgs->nBest;
    pArgs->nCacheOnly     = pOptionArgs->nCacheOnly;
    pArgs->nDebugSolver   = pOptionArgs->nDebugSolver;
    pArgs->nNoGPGCheck    = pOptionArgs->nNoGPGCheck;
    pArgs->nRefresh       = pOptionArgs->nRefresh;
    pArgs->nShowDuplicates= pOptionArgs->nShowDuplicates;
    pArgs->nShowHelp      = pOptionArgs->nShowHelp;
    pArgs->nShowVersion   = pOptionArgs->nShowVersion;
    pArgs->nVerbose       = pOptionArgs->nVerbose;
    pArgs->nIPv4          = pOptionArgs->nIPv4;
    pArgs->nIPv6          = pOptionArgs->nIPv6;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_parse_option(
    const char* pszName,
    const char* pszArg,
    PTDNF_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!pszName || !pCmdArgs)
    {
        dwError = ERROR_PMD_CLI_INVALID_ARGUMENT;
        BAIL_ON_CLI_ERROR(dwError);
    }
    dwError = pkg_validate_options(pszName, pszArg, pstOptions);
    BAIL_ON_CLI_ERROR(dwError);

    if(!strcasecmp(pszName, "enablerepo"))
    {
        if(!optarg)
        {
            dwError = ERROR_PMD_CLI_OPTION_ARG_REQUIRED;
            BAIL_ON_CLI_ERROR(dwError);
        }
        fprintf(stdout, "EnableRepo: %s\n", optarg);
    }
    else if(!strcasecmp(pszName, "disablerepo"))
    {
        if(!optarg)
        {
            dwError = ERROR_PMD_CLI_OPTION_ARG_REQUIRED;
            BAIL_ON_CLI_ERROR(dwError);
        }
        fprintf(stdout, "DisableRepo: %s\n", optarg);
    }
cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pkg_handle_options_error(
    const char* pszName,
    const char* pszArg,
    struct option* pstOptions
    )
{
    uint32_t dwError = 0;

    dwError = pkg_validate_options(
                  pszName,
                  pszArg,
                  pstOptions);
    if(dwError == ERROR_PMD_CLI_OPTION_NAME_INVALID)
    {
       show_no_such_option(pszName);
    }
    return dwError;
}

uint32_t
pkg_parse_info_args(
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_LIST_ARGS* ppListArgs
    )
{
    return TDNFCliParseListArgs(
        pCmdArgs,
        ppListArgs);
}

void
pkg_free_cmd_args(
    PTDNF_CMD_ARGS pCmdArgs
    )
{
    int nIndex = 0;
    if(pCmdArgs)
    {
        for(nIndex = 0; nIndex < pCmdArgs->nCmdCount; ++nIndex)
        {
            PMD_SAFE_FREE_MEMORY(pCmdArgs->ppszCmds[nIndex]);
        }
        PMD_SAFE_FREE_MEMORY(pCmdArgs->ppszCmds);
    }
    PMD_SAFE_FREE_MEMORY(pCmdArgs);
}
