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
pkg_get_rpc_cmd_args(
    PTDNF_CMD_ARGS pArgs,
    PTDNF_RPC_CMD_ARGS *ppRpcArgs
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    PTDNF_RPC_CMD_ARGS pRpcArgs = NULL;

    if(!pArgs || !ppRpcArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(TDNF_RPC_CMD_ARGS),
                  (void **)&pRpcArgs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(
                  sizeof(PMD_WSTRING_ARRAY),
                  (void **)&pRpcArgs->pCmds);
    BAIL_ON_PMD_ERROR(dwError);

    if(pArgs->nCmdCount > 0)
    {
        dwError = PMDAllocateMemory(
                      sizeof(wstring_t) * pArgs->nCmdCount,
                      (void **)&pRpcArgs->pCmds->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRpcArgs->pCmds->dwCount = pArgs->nCmdCount;
    for(i = 0; i < pArgs->nCmdCount; ++i)
    {
        dwError = PMDAllocateStringWFromA(
                      pArgs->ppszCmds[i],
                      &pRpcArgs->pCmds->ppwszStrings[i]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRpcArgs = pRpcArgs;
cleanup:
    return dwError;

error:
    if(ppRpcArgs)
    {
        *ppRpcArgs = NULL;
    }
    free_pkg_rpc_cmd_args(pRpcArgs);
    goto cleanup;
}

void
free_pkg_rpc_cmd_args(
    PTDNF_RPC_CMD_ARGS pArgs
    )
{
    if(!pArgs)
    {
        return;
    }
    PMDFreeStringArrayWithCount((char **)pArgs->pCmds->ppwszStrings,
                                pArgs->pCmds->dwCount);
    PMD_SAFE_FREE_MEMORY(pArgs->pCmds);
    PMD_SAFE_FREE_MEMORY(pArgs);
}
