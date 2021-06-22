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

    if(pArgs->pSetOpt)
    {
        PTDNF_CMD_OPT pSetOpt = pArgs->pSetOpt;
        uint32_t nOptCount = 0;


        dwError = PMDAllocateMemory(
                        sizeof(TDNF_RPC_CMD_OPT_ARRAY),
                        (void **)&pRpcArgs->pSetOptArray);

        while(pSetOpt)
        {
            nOptCount++;
            pSetOpt = pSetOpt->pNext;
        }

        pRpcArgs->pSetOptArray->dwCount = nOptCount;
        dwError = PMDAllocateMemory(
                            sizeof(TDNF_RPC_CMD_OPT) * pRpcArgs->pSetOptArray->dwCount,
                            (void **)&pRpcArgs->pSetOptArray->pCmdOpt);
        BAIL_ON_PMD_ERROR(dwError);

        pSetOpt = pArgs->pSetOpt;
        for(i = 0; i < pRpcArgs->pSetOptArray->dwCount; ++i)
        {
            pRpcArgs->pSetOptArray->pCmdOpt[i].nType = pSetOpt->nType;

            dwError = PMDAllocateStringWFromA(
                                        pSetOpt->pszOptName,
                                        &pRpcArgs->pSetOptArray->pCmdOpt[i].pwszOptName);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = PMDAllocateStringWFromA(
                                        pSetOpt->pszOptValue,
                                        &pRpcArgs->pSetOptArray->pCmdOpt[i].pwszOptValue);
            BAIL_ON_PMD_ERROR(dwError);

            pSetOpt = pSetOpt->pNext;
        }
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

    if(pArgs->pSetOptArray != NULL)
    {
        PMDFreeCmdOptWithCount(pArgs->pSetOptArray->pCmdOpt,
                              pArgs->pSetOptArray->dwCount);
        PMD_SAFE_FREE_MEMORY(pArgs->pSetOptArray);
    }

    PMD_SAFE_FREE_MEMORY(pArgs);
}

void
PMDFreeCmdOptWithCount(
    PTDNF_RPC_CMD_OPT pCmdOpt,
    int dwCount)
{
    if(pCmdOpt)
    {
        for(int i=0; i<dwCount; ++i)
        {
            PMDFreeMemory((&pCmdOpt[i])->pwszOptName);
            PMDFreeMemory((&pCmdOpt[i])->pwszOptValue);
        }
        PMDFreeMemory(pCmdOpt);
    }
}

void
PMDFreeRpcRepoSyncArgs(
    PTDNF_RPC_REPOSYNC_ARGS pRpcRepoSyncArgs
    )
{
    if(!pRpcRepoSyncArgs)
    {
        return;
    }

    if(pRpcRepoSyncArgs->pArchs && pRpcRepoSyncArgs->pArchs->ppwszStrings)
    {
        PMDFreeStringArrayWithCount(
                            (char **)pRpcRepoSyncArgs->pArchs->ppwszStrings,
                            pRpcRepoSyncArgs->pArchs->dwCount);
    }

    PMD_SAFE_FREE_MEMORY(pRpcRepoSyncArgs->pArchs);

    PMD_SAFE_FREE_MEMORY(pRpcRepoSyncArgs);
}

uint32_t
PMDRpcClientConvertRpcRepoSyncArgs(
    PTDNF_REPOSYNC_ARGS pRepoSyncArgs,
    PTDNF_RPC_REPOSYNC_ARGS *ppRpcRepoSyncArgs
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    uint32_t i = 0;
    PTDNF_RPC_REPOSYNC_ARGS pRpcRepoSyncArgs = NULL;

    if(!pRepoSyncArgs || !ppRpcRepoSyncArgs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(TDNF_RPC_REPOSYNC_ARGS),
                  (void **)&pRpcRepoSyncArgs);
    BAIL_ON_PMD_ERROR(dwError);

    pRpcRepoSyncArgs->nDelete           = pRepoSyncArgs->nDelete;
    pRpcRepoSyncArgs->nDownloadMetadata = pRepoSyncArgs->nDownloadMetadata;
    pRpcRepoSyncArgs->nGPGCheck         = pRepoSyncArgs->nGPGCheck;
    pRpcRepoSyncArgs->nNewestOnly       = pRepoSyncArgs->nNewestOnly;
    pRpcRepoSyncArgs->nPrintUrlsOnly    = pRepoSyncArgs->nPrintUrlsOnly;
    pRpcRepoSyncArgs->nNoRepoPath       = pRepoSyncArgs->nNoRepoPath;
    pRpcRepoSyncArgs->nSourceOnly       = pRepoSyncArgs->nSourceOnly;

    if(!IsNullOrEmptyString(pRepoSyncArgs->pszDownloadPath))
    {
        dwError = PMDAllocateStringWFromA(
                      pRepoSyncArgs->pszDownloadPath,
                      &pRpcRepoSyncArgs->pszDownloadPath);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pRepoSyncArgs->pszMetaDataPath))
    {
        dwError = PMDAllocateStringWFromA(
                      pRepoSyncArgs->pszMetaDataPath,
                      &pRpcRepoSyncArgs->pszMetaDataPath);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pRepoSyncArgs->ppszArchs)
    {
        for (i = 0; pRepoSyncArgs->ppszArchs[i] && i < TDNF_REPOSYNC_MAXARCHS; i++)
        {
            ++dwCount;
        }

        dwError = PMDAllocateMemory(
                      sizeof(PMD_WSTRING_ARRAY),
                      (void **)&pRpcRepoSyncArgs->pArchs);
        BAIL_ON_PMD_ERROR(dwError);

        pRpcRepoSyncArgs->pArchs->dwCount = dwCount;

        dwError = PMDAllocateMemory(
                    sizeof(wstring_t) * (dwCount + 1),
                    (void **)&pRpcRepoSyncArgs->pArchs->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < dwCount; i++)
        {
            if(pRepoSyncArgs->ppszArchs != NULL && pRepoSyncArgs->ppszArchs[i] != NULL)
            {
                dwError = PMDAllocateStringWFromA(
                              pRepoSyncArgs->ppszArchs[i],
                              &pRpcRepoSyncArgs->pArchs->ppwszStrings[i]);
                BAIL_ON_PMD_ERROR(dwError);
            }
        }
    }

    *ppRpcRepoSyncArgs = pRpcRepoSyncArgs;

cleanup:
    return dwError;

error:
    if(ppRpcRepoSyncArgs)
    {
        *ppRpcRepoSyncArgs = NULL;
    }

    PMDFreeRpcRepoSyncArgs(pRpcRepoSyncArgs);

    goto cleanup;
}
