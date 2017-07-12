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

//Does command dispatch
//Commands are of the form: pmd-cli <component> [options] <command>
//Command eg: pmd-cli net list routes -6
//component will be identified as "net" here, then routed accordingly
int main(int argc, char* argv[])
{
    uint32_t dwError = 0;
    PPMD_CMD_ARGS pCmdArgs = NULL;
    char** argvDup = NULL;

    dwError = dup_argv(argc, argv, &argvDup);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = parse_comp_cmd(argc, argvDup, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = route_cmd(argc, argv, pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(argvDup, argc);
    free_cmd_args(pCmdArgs);
    return dwError;
error:
    if(dwError != ERROR_PMD_FAIL)
    {
        print_error(dwError);
    }
    dwError = 1;
    goto cleanup;
}

uint32_t
route_cmd(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    PMD_KNOWN_COMPONENT arKnownComps[] =
    {
#ifdef DEMO_ENABLED
        {"demo", "demo", demo_main},
#endif
        {"firewall", "firewall management", fwmgmt_main},
        {"net", "network management", netmgr_main},
        {"pkg", "package management", pkg_main},
        {"usr", "user management", usermgmt_main},
        {"gp", "group policy management", gpmgmt_main},
        {NULL, NULL, NULL}
    };
    int nIndex = 0;
    char* pszName = NULL;
    PFN_COMP_MAIN pfnMain = NULL;

    if(!argv || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(argc < 2 || !pCmdArgs->ppszCmds)
    {
        dwError = ERROR_PMD_CLI_NOT_ENOUGH_ARGS;
        BAIL_ON_CLI_ERROR(dwError);
    }

    pszName = pCmdArgs->ppszCmds[0];

    while(arKnownComps[nIndex].pszName)
    {
        if(!strcasecmp(arKnownComps[nIndex].pszName, pszName))
        {
            pfnMain = arKnownComps[nIndex].pfnMain;
            break;
        }
        ++nIndex;
    }

    if(!pfnMain)
    {
        dwError = ESRCH;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pCmdArgs->pszUser))
    {
        fprintf(stdout, "Password: ");

        dwError = read_password_no_echo(&pCmdArgs->pszPass);
        fprintf(stdout, "\n");
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = pfnMain(argc, argv, pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    if(dwError == ERROR_PMD_CLI_NOT_ENOUGH_ARGS)
    {
        ShowRegisteredComponents(arKnownComps);
        show_usage();
    }
    if(dwError == ESRCH)
    {
        fprintf(stderr, "Component %s is not known\n", pszName);
        ShowRegisteredComponents(arKnownComps);
    }
    goto cleanup;
}

void
ShowRegisteredComponents(
    PPMD_KNOWN_COMPONENT pKnownComps
    )
{
   int nIndex = 0;
   printf("These are the current registered components\n");
   while(pKnownComps->pszName)
   {
       printf(" '%s' : %s\n",
              pKnownComps->pszName,
              pKnownComps->pszDescription);
       ++pKnownComps;
   }
}

uint32_t
print_error(
    uint32_t dwErrorCode
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;

    if(dwErrorCode < ERROR_PMD_BASE)
    {
        dwError = PMDGetErrorString(dwErrorCode, &pszError);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else if(PMDIsSystemError(dwErrorCode))
    {
        dwError = PMDGetSystemErrorString(dwErrorCode, &pszError);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else
    {
        dwError = PMDGetErrorString(dwErrorCode, &pszError);
        BAIL_ON_CLI_ERROR(dwError);
    }
    printf("Error(%d) : %s\n", dwErrorCode, pszError);

cleanup:
    PMD_CLI_SAFE_FREE_MEMORY(pszError);
    return dwError;

error:
    printf(
        "Retrieving error string for %d failed with %d\n",
        dwErrorCode,
        dwError);
    goto cleanup;
}
