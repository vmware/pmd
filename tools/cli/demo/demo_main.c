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
demo_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    PDEMO_CMD_ARGS pCmdArgs = NULL;
    DEMO_CLI_CMD_MAP arCmdMap[] =
    {
        {"isprime",      demo_isprime_cmd},
        {"primes",       demo_primes_cmd},
//        {"fav",          demo_fav_cmd},
        {"version",      demo_show_version_cmd},
    };
    int nCommandCount = sizeof(arCmdMap)/sizeof(DEMO_CLI_CMD_MAP);
    const char* pszCmd = NULL;
    int nFound = 0;

    dwError = demo_parse_args(argc, argv, &pCmdArgs);
    BAIL_ON_CLI_ERROR(dwError);

    if(pCmdArgs->nShowHelp)
    {
        demo_show_help();
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
                              "demo",
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
        demo_show_help();
    }

cleanup:
    if(hPMD)
    {
        PMDFreeHandle(hPMD);
    }
    if(pCmdArgs)
    {
        demo_free_cmd_args(pCmdArgs);
    }
    return dwError;

error:
    //demo_print_error(dwError);
    goto cleanup;
}

uint32_t
demo_show_version_cmd(
    PPMDHANDLE hPMD,
    PDEMO_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = demo_client_version(hPMD, &pszVersion);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "version: %s\n", pszVersion);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return dwError;
error:
    goto cleanup;
}

uint32_t
demo_isprime_cmd(
    PPMDHANDLE hPMD,
    PDEMO_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    int nNumToCheck = 0;
    int nIsPrime = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 2)
    {
        fprintf(stderr, "you must specify a number to check\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    nNumToCheck = atoi(pCmdArgs->ppszCmds[1]);

    dwError = demo_client_isprime(hPMD, nNumToCheck, &nIsPrime);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout, "%d is %sprime\n", nNumToCheck, nIsPrime ? "" : "not ");

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
demo_primes_cmd(
    PPMDHANDLE hPMD,
    PDEMO_CMD_ARGS pCmdArgs
    )
{
    uint32_t dwError = 0;
    int i = 0;
    int nStart = 0;
    int nCount = 0;
    int *pnPrimes = NULL;
    int nNumPrimes = 0;

    if(!hPMD || !pCmdArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if(pCmdArgs->nCmdCount < 3)
    {
        fprintf(stderr, "you must specify a start number and a count\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    nStart = atoi(pCmdArgs->ppszCmds[1]);
    nCount = atoi(pCmdArgs->ppszCmds[2]);

    dwError = demo_client_primes(hPMD, nStart, nCount, &pnPrimes, &nNumPrimes);
    BAIL_ON_CLI_ERROR(dwError);

    fprintf(stdout,
            "primes between %d and %d: %d\n",
            nStart,
            nStart + nCount,
            nNumPrimes);
    for(i = 0; i < nNumPrimes; ++i)
    {
        fprintf(stdout, "%d, ", pnPrimes[i]);
        if(i > 0 && i % 7 == 0)
        {
             fprintf(stdout, "\n");
        }
    }
    fprintf(stdout, "\n");

cleanup:
    PMD_SAFE_FREE_MEMORY(pnPrimes);
    return dwError;
error:
    goto cleanup;
}
