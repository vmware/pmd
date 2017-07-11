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
rolemgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PROLEMGMT_CMD_ARGS pCmdArgs = NULL;
    ROLEMGMT_CLI_CMD_MAP arCmdMap[] =
    {
        {"roles",       rolemgmt_cli_roles_cmd},
        {"version",     rolemgmt_cli_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(ROLEMGMT_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    dwError = rolemgmt_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        rolemgmt_cli_show_help();
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
                              "rolemgmt",
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
        rolemgmt_cli_show_help();
    }

cleanup:
    if(hPMD)
    {
        PMDFreeHandle(hPMD);
    }
    if(pCmdArgs)
    {
        rolemgmt_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
print_task_logs(
    PPMD_ROLEMGMT_TASK_LOG pTaskLogs,
    uint32_t dwTaskLogCount
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;

    if(!pTaskLogs || dwTaskLogCount == 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    for(i = 0; i < dwTaskLogCount; ++i)
    {
        fprintf(stdout, "%s\n", pTaskLogs[i].pszLog);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}


uint32_t
rolemgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = rolemgmt_get_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_roles_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    switch(pCmdArgs->nOperation)
    {
        case ROLEMGMT_OPERATION_LIST:
            dwError = rolemgmt_cli_get_roles_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_VERSION:
            dwError = rolemgmt_cli_get_version_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_LOGS:
            dwError = rolemgmt_cli_get_logs_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_PREREQS:
            dwError = rolemgmt_cli_get_prereqs_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_STATUS:
            dwError = rolemgmt_cli_get_status_cmd(hPMD, pCmdArgs);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_ENABLE:
            dwError = rolemgmt_cli_alter_cmd(
                          hPMD,
                          pCmdArgs,
                          ROLE_OPERATION_ENABLE);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_REMOVE:
            dwError = rolemgmt_cli_alter_cmd(
                          hPMD,
                          pCmdArgs,
                          ROLE_OPERATION_REMOVE);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        case ROLEMGMT_OPERATION_UPDATE:
            dwError = rolemgmt_cli_alter_cmd(
                          hPMD,
                          pCmdArgs,
                          ROLE_OPERATION_UPDATE);
            BAIL_ON_CLI_ERROR(dwError);
        break;
        default:
            fprintf(stderr,
                    "Invalid operation.\
                     Specify --list(default)|--set|--delete\n");
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_CLI_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_get_roles_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;

    dwError = rolemgmt_get_roles(hPMD, &pRoles);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "Available roles:\n\n");
    for(pRole = pRoles; pRole; pRole = pRole->pNext)
    {
        fprintf(stdout, "%s\n", pRole->pszRole);
        fprintf(stdout, "Id          : %s\n", pRole->pszId);
        fprintf(stdout, "Name        : %s\n", pRole->pszName);
        fprintf(stdout, "Description : %s\n", pRole->pszDescription);
        fprintf(stdout, "\n");
    }

cleanup:
    rolemgmt_free_roles(pRoles);
    return dwError;

error:
    if(dwError == ERROR_PMD_NO_DATA)
    {
        fprintf(stderr, "There are no roles configured. Role configuration is read from \".role\" files under /etc/javelin.roles.d or from a directory configured under the \"roles\" section in /etc/pmd/pmd.conf.\n");
    }
    goto cleanup;
}

uint32_t
rolemgmt_cli_get_logs_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_TASK_LOG pTaskLogs = NULL;
    uint32_t dwOffset = 0;
    uint32_t dwTaskLogCount = 0;
    PMD_ROLE_STATUS nStatus = ROLE_STATUS_NONE;

    if(!hPMD || !pCmdArgs || IsNullOrEmptyString(pCmdArgs->pszTaskUUID))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    do
    {
        dwError = rolemgmt_get_log(
                      hPMD,
                      pCmdArgs->pszTaskUUID,
                      dwOffset,
                      1,
                      &pTaskLogs,
                      &dwTaskLogCount);

        if(dwError == ERROR_PMD_ROLE_TASK_NO_LOGS)
        {
            dwError = rolemgmt_get_status(
                          hPMD,
                          pCmdArgs->pszName,
                          pCmdArgs->pszTaskUUID,
                          &nStatus);
            BAIL_ON_CLI_ERROR(dwError);

            if(nStatus == ROLE_STATUS_IN_PROGRESS)
            {
                fprintf(stdout, "Task is in progress. Waiting for more logs..\n");
                dwError = 0;
                sleep(1);
                continue;
            }
        }
        BAIL_ON_CLI_ERROR(dwError);

        if(pTaskLogs)
        {
            dwError = print_task_logs(pTaskLogs, dwTaskLogCount);
            BAIL_ON_CLI_ERROR(dwError);
        }

        //wait a bit
        sleep(1);
        dwOffset += dwTaskLogCount;
    }while(dwTaskLogCount > 0);

cleanup:
    return dwError;

error:
    goto cleanup;
}


uint32_t
rolemgmt_cli_get_version_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!hPMD || !pCmdArgs || IsNullOrEmptyString(pCmdArgs->pszRole))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = rolemgmt_get_role_version(hPMD, pCmdArgs->pszRole, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "Version of %s : %s\n", pCmdArgs->pszRole, pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_get_prereqs_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    uint32_t dwPrereqCount = 0;
    uint32_t i = 0;
    char *pszVersion = NULL;
    PPMD_ROLE_PREREQ pPrereqs = NULL;
    PMD_ROLE_OPERATION nOperation = ROLE_OPERATION_NONE;

    if(!hPMD || !pCmdArgs || IsNullOrEmptyString(pCmdArgs->pszRole))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = rolemgmt_get_prereqs(hPMD,
                                   pCmdArgs->pszRole,
                                   nOperation,
                                   &pPrereqs,
                                   &dwPrereqCount);
    BAIL_ON_CLI_ERROR(dwError);

    if(dwPrereqCount == 0)
    {
        fprintf(stdout, "There are no prereqs for %s\n", pCmdArgs->pszRole);
    }
    else
    {
        fprintf(stdout, "Prereqs for %s\n", pCmdArgs->pszRole);

        for(i = 0; i < dwPrereqCount; ++i)
        {
            fprintf(stdout, "  %d. %s - %s\n",
                    i+1,
                    pPrereqs[i].pszName,
                    pPrereqs[i].pszDescription);
        }
    }
cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_get_status_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PMD_ROLE_STATUS nStatus = ROLE_STATUS_NONE;
    char* pszStatus = NULL;

    if(!hPMD ||
       !pCmdArgs ||
       IsNullOrEmptyString(pCmdArgs->pszRole) ||
       IsNullOrEmptyString(pCmdArgs->pszTaskUUID))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = rolemgmt_get_status(
                  hPMD,
                  pCmdArgs->pszRole,
                  pCmdArgs->pszTaskUUID,
                  &nStatus);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = rolemgmt_status_to_string(nStatus, &pszStatus);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "Status: %s\n", pszStatus);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_cli_alter_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs,
    PMD_ROLE_OPERATION nOperation
    )
{
    uint32_t dwError = 0;
    char *pszConfigJson = NULL;
    char *pszTaskUUID = NULL;
    uint32_t dwOffset = 0;
    uint32_t dwEntriesToFetch = 1;
    PPMD_ROLEMGMT_TASK_LOG pTaskLogs = NULL;
    uint32_t dwTaskLogCount = 0;
    PMD_ROLE_STATUS nStatus = ROLE_STATUS_NONE;

    if(!hPMD ||
       !pCmdArgs ||
       IsNullOrEmptyString(pCmdArgs->pszRole)) 
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(nOperation == ROLE_OPERATION_ENABLE &&
       IsNullOrEmptyString(pCmdArgs->pszConfigFile))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pCmdArgs->pszConfigFile))
    {
        dwError = file_read_all_text(pCmdArgs->pszConfigFile, &pszConfigJson);
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = rolemgmt_alter(
                  hPMD,
                  pCmdArgs->pszRole,
                  nOperation,
                  pszConfigJson,
                  &pszTaskUUID);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout,
            "Add role task for %s is queued with id: %s\n",
            pCmdArgs->pszRole,
            pszTaskUUID);

    nStatus = ROLE_STATUS_IN_PROGRESS;
    while(nStatus == ROLE_STATUS_IN_PROGRESS)
    {
        dwError = rolemgmt_get_status(
                      hPMD,
                      pCmdArgs->pszRole,
                      pszTaskUUID,
                      &nStatus);
        BAIL_ON_CLI_ERROR(dwError);

        dwError = rolemgmt_get_log(
                      hPMD,
                      pszTaskUUID,
                      dwOffset,
                      dwEntriesToFetch,
                      &pTaskLogs,
                      &dwTaskLogCount);
        if(dwError == ERROR_PMD_ROLE_TASK_NO_LOGS || dwError == ERROR_PMD_NO_DATA)
        {
            dwError = 0;
        }
        else if(!dwError && pTaskLogs)
        {
            dwError = print_task_logs(pTaskLogs, dwTaskLogCount);
            BAIL_ON_CLI_ERROR(dwError);
        }
        BAIL_ON_CLI_ERROR(dwError);

        //wait a bit
        sleep(1);
        dwOffset += dwTaskLogCount;
    }

    if(pTaskLogs != NULL)
    {
        fprintf(stdout, "log = %s\n", pTaskLogs[0].pszLog);
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszConfigJson);
    PMD_SAFE_FREE_MEMORY(pszTaskUUID);
    return dwError;

error:
    goto cleanup;
}
