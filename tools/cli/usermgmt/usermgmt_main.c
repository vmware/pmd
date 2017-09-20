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
usermgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PUSERMGMT_CMD_ARGS pCmdArgs = NULL;
    USERMGMT_CLI_CMD_MAP arCmdMap[] =
    {
        {"useradd",     usermgmt_cli_useradd_cmd},
        {"userdel",     usermgmt_cli_userdel_cmd},
        {"groupadd",    usermgmt_cli_groupadd_cmd},
        {"groupdel",    usermgmt_cli_groupdel_cmd},
        {"groupid",     usermgmt_cli_get_groupid_cmd},
        {"groups",      usermgmt_cli_get_groups_cmd},
        {"userid",      usermgmt_cli_get_userid_cmd},
        {"users",       usermgmt_cli_get_users_cmd},
        {"version",     usermgmt_cli_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(USERMGMT_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    dwError = usermgmt_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        usermgmt_cli_show_help();
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
                              "usermgmt",
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
        usermgmt_cli_show_help();
    }

cleanup:
    rpc_free_handle(hPMD);
    if(pCmdArgs)
    {
        usermgmt_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = usermgmt_get_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}

uint32_t
usermgmt_cli_get_userid_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszName = NULL;
    uint32_t nUID = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "please specify a user name\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[1];

    dwError = usermgmt_get_userid(hPMD, pszName, &nUID);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "uid for user %s : %d\n", pszName, nUID);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_get_groupid_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszName = NULL;
    uint32_t nGID = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "please specify a group name\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[1];

    dwError = usermgmt_get_groupid(hPMD, pszName, &nGID);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "gid for group %s : %d\n", pszName, nGID);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_get_users_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_USER pUsers = NULL;
    PPMD_USER pUser = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = usermgmt_get_users(hPMD, &pUsers);
    BAIL_ON_CLI_ERROR(dwError);

    for(pUser = pUsers; pUser; pUser = pUser->pNext)
    {
        printf("%s  %d  %s  %s  %s\n",
               pUser->pszName,
               pUser->nUID,
               pUser->pszRealName,
               pUser->pszHomeDir,
               pUser->pszShell);
    }

cleanup:
    usermgmt_free_user(pUsers);
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_get_groups_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_GROUP pGroups = NULL;
    PPMD_GROUP pGroup = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = usermgmt_get_groups(hPMD, &pGroups);
    BAIL_ON_CLI_ERROR(dwError);

    for(pGroup = pGroups; pGroup; pGroup = pGroup->pNext)
    {
        printf("%s  %d\n",
               pGroup->pszName,
               pGroup->nGID);
    }

cleanup:
    usermgmt_free_group(pGroups);
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_useradd_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "please specify user name\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[1];

    dwError = usermgmt_add_user(hPMD, pszName);
    if(dwError == ERROR_PMD_ALREADY_EXISTS)
    {
        dwError = ERROR_PMD_FAIL;//prevent further error analysis
        fprintf(stderr, "User '%s' already exists.\n", pszName);
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_userdel_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "please specify user name\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[1];

    dwError = usermgmt_delete_user(hPMD, pszName);
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = ERROR_PMD_FAIL;//prevent further error analysis
        fprintf(stderr, "User '%s' does not exist.\n", pszName);
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_groupadd_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "please specify group name\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[1];

    dwError = usermgmt_add_group(hPMD, pszName);
    if(dwError == ERROR_PMD_ALREADY_EXISTS)
    {
        dwError = ERROR_PMD_FAIL;//prevent further error analysis
        fprintf(stderr, "Group '%s' already exists.\n", pszName);
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
usermgmt_cli_groupdel_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "please specify group name\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[1];

    dwError = usermgmt_delete_group(hPMD, pszName);
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = ERROR_PMD_FAIL;//prevent further error analysis
        fprintf(stderr, "Group '%s' does not exist.\n", pszName);
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}
