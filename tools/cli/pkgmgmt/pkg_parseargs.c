/*
 * Copyright © 2016-2021 VMware, Inc.  All Rights Reserved.
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

typedef struct _SetOptArgs
{
    TDNF_CMDOPT_TYPE Type;
    const char *OptName;
    const char *OptVal;
} SetOptArgs;

static SetOptArgs OptValTable[] =
{
    {CMDOPT_KEYVALUE, "sec-severity", NULL},
    {CMDOPT_ENABLEREPO, "enablerepo", NULL},
    {CMDOPT_DISABLEREPO, "disablerepo", NULL},
    {CMDOPT_ENABLEPLUGIN, "enableplugin", NULL},
    {CMDOPT_DISABLEPLUGIN, "disableplugin", NULL},
    {CMDOPT_KEYVALUE, "skipconflicts;skipobsoletes;skipsignature;skipdigest;"
                        "noplugins;reboot-required;security"
                        "delete;download-metadata;gpgcheck;newest-only;norepopath;source;urls",
                        "1"}
};

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
    {"exclude",       required_argument, 0, 0},            //--exclude
    {"security",      no_argument, 0, 0},                  //--security
    {"sec-severity",  required_argument, 0, 0},            //--sec-severity
    {"reboot-required", no_argument, 0, 0},                //--reboot-required
    {"skipconflicts", no_argument, 0, 0},                  //--skipconflicts to skip conflict problems
    {"skipobsoletes", no_argument, 0, 0},                  //--skipobsoletes to skip obsolete problems
    {"skipsignature", no_argument, 0, 0},                  //--skipsignature to skip verifying RPM signatures
    {"skipdigest",    no_argument, 0, 0},                  //--skipdigest to skip verifying RPM digest
    {"noplugins",     no_argument, 0, 0},                  //--noplugins
    {"disableplugin", required_argument, 0, 0},            //--disableplugin
    {"enableplugin",  required_argument, 0, 0},            //--enableplugin
    {"disableexcludes", no_argument, &_opt.nDisableExcludes, 1}, //--disableexcludes
    {"downloadonly",  no_argument, &_opt.nDownloadOnly, 1}, //--downloadonly
    {"downloaddir",   required_argument, 0, 0},            //--downloaddir
    // reposync options
    {"arch",          required_argument, 0, 0},
    {"delete",        no_argument, 0, 0},
    {"download-metadata", no_argument, 0, 0},
    {"gpgcheck", no_argument, 0, 0},
    {"metadata-path", required_argument, 0, 0},
    {"newest-only",   no_argument, 0, 0},
    {"norepopath",    no_argument, 0, 0},
    {"download-path", required_argument, 0, 0},
    {"source",        no_argument, 0, 0},
    {"urls",          no_argument, 0, 0},
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
    pArgs->nNoOutput      = pOptionArgs->nQuiet && pOptionArgs->nAssumeYes;
    pArgs->nQuiet         = pOptionArgs->nQuiet;
    pArgs->nRefresh       = pOptionArgs->nRefresh;
    pArgs->nShowDuplicates= pOptionArgs->nShowDuplicates;
    pArgs->nShowHelp      = pOptionArgs->nShowHelp;
    pArgs->nShowVersion   = pOptionArgs->nShowVersion;
    pArgs->nVerbose       = pOptionArgs->nVerbose;
    pArgs->nIPv4          = pOptionArgs->nIPv4;
    pArgs->nIPv6          = pOptionArgs->nIPv6;
    pArgs->nDisableExcludes = pOptionArgs->nDisableExcludes;
    pArgs->nDownloadOnly  = pOptionArgs->nDownloadOnly;

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
    const char *OptVal = NULL;
    uint32_t i = 0;
    char *pszCopyArgs = NULL;
    char *ToFree = NULL;
    char *pszToken = NULL;

    if(!pszName || !pCmdArgs)
    {
        dwError = ERROR_PMD_CLI_INVALID_ARGUMENT;
        BAIL_ON_CLI_ERROR(dwError);
    }
    dwError = pkg_validate_options(pszName, pszArg, pstOptions);
    BAIL_ON_CLI_ERROR(dwError);

    if (!strcasecmp(pszName, "config"))
    {
        dwError = PMDSafeAllocateString(optarg, &pCmdArgs->pszConfFile);
    }
    else if (!strcasecmp(pszName, "rpmverbosity"))
    {
        dwError = parse_rpm_verbosity(pszArg, &pCmdArgs->nRpmVerbosity);
    }
    else if (!strcasecmp(pszName, "installroot"))
    {
        dwError = PMDSafeAllocateString(optarg, &pCmdArgs->pszInstallRoot);
    }
    else if (!strcasecmp(pszName, "downloaddir"))
    {
        dwError = PMDSafeAllocateString(optarg, &pCmdArgs->pszDownloadDir);
    }
    else if (!strcasecmp(pszName, "releasever"))
    {
        dwError = PMDSafeAllocateString(optarg, &pCmdArgs->pszReleaseVer);
    }
    else if ((!strcasecmp(pszName, "metadata-path")) ||
             (!strcasecmp(pszName, "download-path")) ||
             (!strcasecmp(pszName, "arch")))
    {
        dwError = add_set_opt_with_values(pCmdArgs,
                            CMDOPT_KEYVALUE,
                            pszName,
                            optarg);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if (!strcasecmp(pszName, "setopt"))
    {
        if (!optarg)
        {
            dwError = ERROR_PMD_CLI_OPTION_ARG_REQUIRED;
            BAIL_ON_CLI_ERROR(dwError);
        }

        dwError = add_set_opt(pCmdArgs, optarg);
        if (dwError == ERROR_PMD_SETOPT_NO_EQUALS)
        {
            dwError = ERROR_PMD_CLI_SETOPT_NO_EQUALS;
        }
    }
    else if (!strcasecmp(pszName, "exclude"))
    {
        dwError = PMDSafeAllocateString(pszArg, &pszCopyArgs);
        BAIL_ON_CLI_ERROR(dwError);

        ToFree = pszCopyArgs;

        while ((pszToken = strsep(&pszCopyArgs, ",:")))
        {
            dwError = add_set_opt_with_values(pCmdArgs,
                                CMDOPT_KEYVALUE,
                                pszName,
                                pszToken);
            BAIL_ON_CLI_ERROR((dwError && (pszCopyArgs = ToFree)));
        }

        pszCopyArgs = ToFree;
    }
    else
    {
       for (i = 0; i < ARRAY_SIZE(OptValTable); i++)
       {
            if (!strstr(OptValTable[i].OptName, pszName))
            {
                continue;
            }

            OptVal = !OptValTable[i].OptVal ? optarg : OptValTable[i].OptVal;

            dwError = add_set_opt_with_values(pCmdArgs,
                                    OptValTable[i].Type,
                                    pszName,
                                    OptVal);

            BAIL_ON_CLI_ERROR(dwError);
            break;
       }
    }

    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCopyArgs);
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

uint32_t
parse_rpm_verbosity(
    const char *pszRpmVerbosity,
    int *pnRpmVerbosity
    )
{
    uint32_t dwError = 0;
    uint32_t nIndex = 0;
    typedef struct _stTemp
    {
        char *pszTypeName;
        int nType;
    } stTemp;

    if (!pszRpmVerbosity || !pnRpmVerbosity)
    {
        return ERROR_PMD_CLI_INVALID_OPTION;
    }

    stTemp stTypes[] =
    {
        {"emergency",  TDNF_RPMLOG_EMERG},
        {"alert",      TDNF_RPMLOG_ALERT},
        {"critical",   TDNF_RPMLOG_CRIT},
        {"error",      TDNF_RPMLOG_ERR},
        {"warning",    TDNF_RPMLOG_WARNING},
        {"notice",     TDNF_RPMLOG_NOTICE},
        {"info",       TDNF_RPMLOG_INFO},
        {"debug",      TDNF_RPMLOG_DEBUG},
    };

    for (nIndex = 0; nIndex < ARRAY_SIZE(stTypes); ++nIndex)
    {
        if (!strcasecmp(stTypes[nIndex].pszTypeName, pszRpmVerbosity))
        {
            *pnRpmVerbosity = stTypes[nIndex].nType;
            return dwError;
        }
    }

    *pnRpmVerbosity = TDNF_RPMLOG_ERR;

    return dwError;
}
