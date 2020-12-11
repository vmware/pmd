/*
 * Copyright © 2019 VMware, Inc.  All Rights Reserved.
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
pmd_rolemgmt_get_version(
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(PMD_ROLEMGMT_VERSION, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_load(
    )
{
    uint32_t dwError = 0;
    int nLocked = 0, nPrefix = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    PPMD_PLUGIN_CONTEXT pContexts = NULL;
    PPMD_PLUGIN_CONTEXT pContext = NULL;
    char pszResolvedPath[PATH_MAX];

    pthread_mutex_lock(&gRoleMgmtEnv.mutexEnv);
    nLocked = 1;

    if(gRoleMgmtEnv.pRoles)
    {
        goto cleanup;
    }

    dwError = rolemgmt_load_roles(
                  PMD_ROLES_DIR,
                  PMD_ROLE_PLUGINS_DIR,
                  &pRoles);
    BAIL_ON_PMD_ERROR(dwError);

    for(pRole = pRoles; pRole; pRole = pRole->pNext)
    {
        dwError = PMDAllocateMemory(sizeof(PMD_PLUGIN_CONTEXT), (void **)&pContext);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pRole->pszId, &pContext->pszPluginId);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringPrintf(
                      &pContext->pszPluginPath,
                      "%s/%s",
                      PMD_ROLE_PLUGINS_DIR,
                      pRole->pszPlugin);
        BAIL_ON_PMD_ERROR(dwError);

        if(NULL == realpath(pContext->pszPluginPath, pszResolvedPath))
        {
            dwError = errno;
            BAIL_ON_PMD_SYSTEM_ERROR(dwError);
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = isStringPrefix(pszResolvedPath,
                      PMD_ROLE_PLUGINS_DIR,
                      &nPrefix);
        BAIL_ON_PMD_ERROR(dwError);

        if(!nPrefix)
        {
            dwError = ERROR_PMD_ROLE_PATH_MISMATCH;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = PMDAllocateMemory(sizeof(PMD_PLUGIN_MODULE),
                                    (void **)&pContext->pModule);
        BAIL_ON_PMD_ERROR(dwError);

        pContext->pNext = pContexts;
        pContexts = pContext;
        pContext = NULL;
    }

    gRoleMgmtEnv.pRoles = pRoles;
    gRoleMgmtEnv.pContexts = pContexts;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gRoleMgmtEnv.mutexEnv);
    }
    return dwError;

error:
    if(dwError == ERROR_PMD_NO_DATA)//no role files. don't fail.
    {
        dwError = 0;
    }
    gRoleMgmtEnv.pRoles = NULL;
    gRoleMgmtEnv.pContexts = NULL;

    rolemgmt_free_roles(pRoles);
    rolemgmt_free_context(pContext);
    rolemgmt_free_contexts(pContexts);
    goto cleanup;
}

void
pmd_rolemgmt_unload(
    )
{
    pthread_mutex_lock(&gRoleMgmtEnv.mutexEnv);

    rolemgmt_free_roles(gRoleMgmtEnv.pRoles);
    gRoleMgmtEnv.pRoles = NULL;

    rolemgmt_free_contexts(gRoleMgmtEnv.pContexts);
    gRoleMgmtEnv.pContexts = NULL;

    pthread_mutex_unlock(&gRoleMgmtEnv.mutexEnv);
}

uint32_t
pmd_load_plugin(
    const char *pszPluginPath,
    const PPMD_PLUGIN_MODULE pModule
    )
{
    uint32_t dwError = 0;
    int nLocked = 0;
    PMD_PLUGIN_MODULE stModule = {0};

    if(IsNullOrEmptyString(pszPluginPath) || !pModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pModule->pHandle)
    {
        goto cleanup;
    }

    if(pModule->nDisabled)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_DISABLED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&pModule->mutexModule);
    nLocked = 1;

    //clear error
    dlerror();

    stModule.pHandle = dlopen (pszPluginPath, RTLD_NOW);
    if(!stModule.pHandle)
    {
        dwError = ERROR_PMD_LIBACC;
        BAIL_ON_PMD_ERROR(dwError);
    }

    stModule.pFnLoad = dlsym(stModule.pHandle,
                             PMD_ROLEPLUGIN_LOAD_INTERFACE);
    if(!stModule.pFnLoad)
    {
        dwError = ERROR_PMD_ROLE_UNMAPPED_LOAD;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = stModule.pFnLoad(&stModule.pInterface);
    BAIL_ON_PMD_ERROR(dwError);

    if(!stModule.pInterface)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_BAD;
        BAIL_ON_PMD_ERROR(dwError);
    }

    //unload can be null.
    stModule.pFnUnload = dlsym(stModule.pHandle,
                               PMD_ROLEPLUGIN_UNLOAD_INTERFACE);

    pModule->pHandle = stModule.pHandle;
    pModule->pFnLoad = stModule.pFnLoad;
    pModule->pFnUnload = stModule.pFnUnload;
    pModule->pInterface = stModule.pInterface;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&pModule->mutexModule);
    }
    return dwError;

error:
    fprintf(stderr, "Error: %d, dlerror: %s", dwError, dlerror());
    if(pModule)
    {
        pModule->nDisabled = 1;
    }
    if(stModule.pHandle)
    {
        dlclose(stModule.pHandle);
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_get_role_plugin(
    const char *pszName,
    PPMD_PLUGIN_MODULE *ppModule
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_CONTEXT pContext = NULL;
    PPMD_PLUGIN_MODULE pModule = NULL;

    if(IsNullOrEmptyString(pszName) || !ppModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pContext = gRoleMgmtEnv.pContexts; pContext; pContext = pContext->pNext)
    {
        if(!strcasecmp(pContext->pszPluginId, pszName))
        {
            break;
        }
    }

    if(!pContext || !pContext->pModule)
    {
        dwError = ERROR_PMD_ROLES_NO_SUCH_ROLE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pModule = pContext->pModule;
    if(!pModule->pHandle)
    {
        if(IsNullOrEmptyString(pContext->pszPluginPath))
        {
            dwError = ERROR_PMD_ROLES_PLUGIN_NOT_SET;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = pmd_load_plugin(pContext->pszPluginPath, pModule);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppModule = pModule;

cleanup:
    return dwError;

error:
    if(ppModule)
    {
        *ppModule = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_role_version(
    const char *pszName,
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    char *pszPlugin = NULL;
    PPMD_PLUGIN_MODULE pModule = NULL;

    if(IsNullOrEmptyString(pszName) || !ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rolemgmt_get_role_plugin(pszName, &pModule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_plugin_get_version(pModule, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszVersion);
    goto cleanup;
}

uint32_t
pmd_rolemgmt_role_get_prereqs(
    const char *pszName,
    PMD_ROLE_OPERATION nOperation,
    PPMD_ROLE_PREREQ *ppPreReqs,
    uint32_t *pdwPreReqCount
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_MODULE pModule = NULL;
    PPMD_ROLE_PREREQ pPreReqs = NULL;
    uint32_t dwPreReqCount = 0;
    PPMD_ROLE_HANDLE pRoleHandle = NULL;

    if(!ppPreReqs || !pdwPreReqCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rolemgmt_get_role_plugin(pszName, &pModule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_plugin_open(pModule, &pRoleHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_plugin_get_prereqs(
                  pModule,
                  nOperation,
                  pRoleHandle,
                  &pPreReqs,
                  &dwPreReqCount);
    BAIL_ON_PMD_ERROR(dwError);

    *ppPreReqs = pPreReqs;
    *pdwPreReqCount = dwPreReqCount;

cleanup:
    if(pRoleHandle)
    {
        pmd_rolemgmt_plugin_close(pModule, pRoleHandle);
    }
    return dwError;

error:
    if(ppPreReqs)
    {
        *ppPreReqs = NULL;
    }
    if(pdwPreReqCount)
    {
        *pdwPreReqCount = 0;
    }
    goto cleanup;
}

uint32_t
rolemgmt_task_progress_cb(
    const char *pszTaskUUID,
    const char *pszProgress
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_TASK pTask = NULL;
    PPMD_PLUGIN_TASK_LOG pLog = NULL;

    if(IsNullOrEmptyString(pszTaskUUID) || IsNullOrEmptyString(pszProgress))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fprintf(stdout, "Task(%s): %s\n", pszTaskUUID, pszProgress);

    dwError = rolemgmt_find_task_by_id(pszTaskUUID, &pTask);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_PLUGIN_TASK_LOG), (void **)&pLog);
    BAIL_ON_PMD_ERROR(dwError);

    pLog->tStamp = time(NULL);

    dwError = PMDAllocateString(pszProgress, &pLog->pszLog);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pTask->pLogData)
    {
        pTask->pLogData = pLog;
    }
    else
    {
        PPMD_PLUGIN_TASK_LOG pTemp = pTask->pLogData;
        while(pTemp->pNext) pTemp = pTemp->pNext;
        pTemp->pNext = pLog;
    }
cleanup:
    return dwError;

error:
    fprintf(stderr, "Callback from plugin caused an error: %d\n", dwError);

    rolemgmt_free_plugin_task_logs(pLog);
    goto cleanup;
}

uint32_t
pmd_rolemgmt_role_create_task(
    PPMD_PLUGIN_MODULE pModule,
    PMD_ROLE_OPERATION nOperation,
    const char *pszConfigJson,
    PPMD_PLUGIN_TASK *ppTask
    )
{
    uint32_t dwError = 0;
    int nLocked = 0;
    PPMD_PLUGIN_TASK pTask = NULL;
    uuid_t uuidTask = {0};

    if(!pModule || IsNullOrEmptyString(pszConfigJson) || !ppTask)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pModule->pCurrentTask)
    {
        dwError = ERROR_PMD_ROLE_PLUGIN_HAS_TASKS;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_PLUGIN_TASK), (void **)&pTask);
    BAIL_ON_PMD_ERROR(dwError);

    pTask->tStart = time(NULL);
    pTask->pFnProgressCallback = rolemgmt_task_progress_cb;
    pTask->nOperation = nOperation;

    dwError = PMDAllocateString(pszConfigJson, &pTask->pszConfigJson);
    BAIL_ON_PMD_ERROR(dwError);

    //make uuid for this task
    uuid_generate(uuidTask);

    dwError = PMDAllocateMemory(sizeof(char) * UUID_STR_LEN,
                                (void **)&pTask->pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_plugin_open(pModule, &pTask->pRoleHandle);
    BAIL_ON_PMD_ERROR(dwError);

    uuid_unparse(uuidTask, pTask->pszTaskUUID);

    pModule->pCurrentTask = pTask;
    *ppTask = pTask;

cleanup:
    return dwError;

error:
    if(ppTask)
    {
        *ppTask = 0;
    }
    rolemgmt_free_plugin_module_task(pModule);
    goto cleanup;
}

uint32_t
rolemgmt_archive_current_task(
    PPMD_PLUGIN_MODULE pModule
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_TASK pTask = NULL;
    if(!pModule || !pModule->pCurrentTask)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pTask = pModule->pCurrentTask;
    pModule->pCurrentTask = NULL;

    pTask->pNext = pModule->pTaskHistory;
    pModule->pTaskHistory = pTask;

    fprintf(stdout, "Archiving task %s\n", pTask->pszTaskUUID);
error:
    return dwError;
}

void *
pmd_rolemgmt_task_thread(
    void *pThreadInfo
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_TASK_THREAD_INFO pTaskThreadInfo = pThreadInfo;
    if (!pTaskThreadInfo ||
        !pTaskThreadInfo->pModule ||
        !pTaskThreadInfo->pTask)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pTaskThreadInfo->pTask->nStatus = ROLE_STATUS_IN_PROGRESS;
    dwError = pmd_rolemgmt_plugin_alter(
                  pTaskThreadInfo->pModule,
                  pTaskThreadInfo->pTask);
    BAIL_ON_PMD_ERROR(dwError);

    pTaskThreadInfo->pTask->nStatus = ROLE_STATUS_SUCCESS;
cleanup:
    if (pTaskThreadInfo)
    {
        rolemgmt_archive_current_task(pTaskThreadInfo->pModule);
        PMDFreeMemory(pTaskThreadInfo);
    }

    return NULL;

error:
    if (pTaskThreadInfo && pTaskThreadInfo->pTask)
    {
        pTaskThreadInfo->pTask->nStatus = ROLE_STATUS_FAILURE;
        pTaskThreadInfo->pTask->dwError = dwError;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_role_alter(
    const char *pszName,
    PMD_ROLE_OPERATION nOperation,
    const char *pszConfigJson,
    char **ppszTaskUUID
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_MODULE pModule = NULL;
    PPMD_PLUGIN_TASK pTask = NULL;
    char *pszTaskUUID = NULL;
    int nLocked = 0;
    PPMD_PLUGIN_TASK_THREAD_INFO pTaskThreadInfo = NULL;

    if(IsNullOrEmptyString(pszName) ||
       IsNullOrEmptyString(pszConfigJson) ||
       !ppszTaskUUID)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rolemgmt_get_role_plugin(pszName, &pModule);
    BAIL_ON_PMD_ERROR(dwError);

    pthread_mutex_lock(&pModule->mutexTasks);
    nLocked = 1;

    dwError = pmd_rolemgmt_role_create_task(
                  pModule,
                  nOperation,
                  pszConfigJson,
                  &pTask);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_PLUGIN_TASK_THREAD_INFO),
                                (void **)&pTaskThreadInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pTaskThreadInfo->pModule = pModule;
    pTaskThreadInfo->pTask = pTask;

    dwError = pthread_create(&pTask->nThreadID,
                             NULL,
                             &pmd_rolemgmt_task_thread,
                             pTaskThreadInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pTask->pszTaskUUID, &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszTaskUUID = pszTaskUUID;
cleanup:
    if(nLocked && pModule)
    {
        pthread_mutex_unlock(&pModule->mutexTasks);
    }
    return dwError;

error:
    if(ppszTaskUUID)
    {
        *ppszTaskUUID = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszTaskUUID);
    //TODO: safely remove this task
    //pmd_rolemgmt_role_remove_task(pTask);
    goto cleanup;
}

uint32_t
rolemgmt_find_archived_task_by_id(
    const char *pszTaskUUID,
    PPMD_PLUGIN_TASK *ppTask
)
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_TASK pTask = NULL;
    PPMD_PLUGIN_CONTEXT pContext = NULL;

    if(IsNullOrEmptyString(pszTaskUUID) || !ppTask)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pContext = gRoleMgmtEnv.pContexts; pContext; pContext = pContext->pNext)
    {
        PPMD_PLUGIN_TASK pCurrentTask = NULL;
        if(!pContext->pModule || !pContext->pModule->pTaskHistory)
        {
            continue;
        }

        pCurrentTask = pContext->pModule->pTaskHistory;
        while(pCurrentTask != NULL)
        {
            if(!strcasecmp(pCurrentTask->pszTaskUUID, pszTaskUUID))
            {
                pTask = pCurrentTask;
                break;
            }
            pCurrentTask = pCurrentTask->pNext;
        }
    }

    if(!pTask)
    {
        dwError = ERROR_PMD_ROLE_TASK_NO_LOGS;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppTask = pTask;
cleanup:
    return dwError;

error:
    if(ppTask)
    {
        *ppTask = NULL;
    }
    goto cleanup;
}

uint32_t
rolemgmt_find_task_by_id(
    const char *pszTaskUUID,
    PPMD_PLUGIN_TASK *ppTask
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_TASK pTask = NULL;
    PPMD_PLUGIN_CONTEXT pContext = NULL;

    if(IsNullOrEmptyString(pszTaskUUID) || !ppTask)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pContext = gRoleMgmtEnv.pContexts; pContext; pContext = pContext->pNext)
    {
        PPMD_PLUGIN_TASK pCurrentTask = NULL;
        if(!pContext->pModule || !pContext->pModule->pCurrentTask)
        {
            continue;
        }
        pCurrentTask = pContext->pModule->pCurrentTask;
        if(!strcasecmp(pCurrentTask->pszTaskUUID, pszTaskUUID))
        {
            pTask = pContext->pModule->pCurrentTask;
            break;
        }
    }

    if(!pTask)
    {
        dwError = ERROR_PMD_ROLE_TASK_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppTask = pTask;

cleanup:
    return dwError;

error:
    if(ppTask)
    {
        *ppTask = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_get_status(
    const char *pszName,
    const char *pszTaskUUID,
    PMD_ROLE_STATUS *pnStatus
    )
{
    uint32_t dwError = 0;
    PPMD_PLUGIN_TASK pTask = NULL;

    if(IsNullOrEmptyString(pszName) ||
       IsNullOrEmptyString(pszTaskUUID) ||
       !pnStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_find_task_by_id(pszTaskUUID, &pTask);
    if (dwError != ERROR_PMD_ROLE_TASK_NOT_FOUND)
    {
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = rolemgmt_find_archived_task_by_id(pszTaskUUID, &pTask);
        BAIL_ON_PMD_ERROR(dwError);
    }
    *pnStatus = pTask->nStatus;

cleanup:
    return dwError;

error:
    if(pnStatus)
    {
        *pnStatus = ROLE_STATUS_NONE;
    }
    goto cleanup;
}

uint32_t
pmd_rolemgmt_get_logs(
    const char *pszTaskUUID,
    uint32_t dwOffset,
    uint32_t dwEntriesToFetch,
    PPMD_PLUGIN_TASK_LOG *ppTaskLogs
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    PPMD_PLUGIN_TASK_LOG pTaskLogs = NULL;
    PPMD_PLUGIN_TASK pTask = NULL;

    if(IsNullOrEmptyString(pszTaskUUID) || !ppTaskLogs)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_find_task_by_id(pszTaskUUID, &pTask);
    if (dwError != ERROR_PMD_ROLE_TASK_NOT_FOUND)
    {
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        dwError = rolemgmt_find_archived_task_by_id(pszTaskUUID, &pTask);
        BAIL_ON_PMD_ERROR(dwError);
    }

    pTaskLogs = pTask->pLogData;
    for(i = 0; pTaskLogs && i < dwOffset; ++i, pTaskLogs = pTaskLogs->pNext);

    if(!pTaskLogs)
    {
        dwError = ERROR_PMD_ROLE_TASK_NO_LOGS;
        BAIL_ON_PMD_ERROR(dwError);
    }
    *ppTaskLogs = pTaskLogs;

cleanup:
    return dwError;

error:
    if(ppTaskLogs)
    {
        *ppTaskLogs = NULL;
    }
    goto cleanup;
}

void
rolemgmt_free_plugin_task_logs(
    PPMD_PLUGIN_TASK_LOG pLogs
    )
{
    if(!pLogs)
    {
        return;
    }
    while(pLogs)
    {
        PPMD_PLUGIN_TASK_LOG pNextLog = pLogs->pNext;
        PMD_SAFE_FREE_MEMORY(pLogs->pszLog);
        PMDFreeMemory(pLogs);
        pLogs = pNextLog;
    }
}

void
rolemgmt_free_plugin_module_task(
    PPMD_PLUGIN_MODULE pModule
    )
{
    PPMD_PLUGIN_TASK pTask = NULL;
    if (!pModule || !pModule->pCurrentTask)
    {
        return;
    }
    pTask = pModule->pCurrentTask;
    PMD_SAFE_FREE_MEMORY(pTask->pszTaskUUID);
    PMD_SAFE_FREE_MEMORY(pTask->pszConfigJson);
    if(pTask->pRoleHandle)
    {
        pmd_rolemgmt_plugin_close(pModule, pTask->pRoleHandle);
    }
    rolemgmt_free_plugin_task_logs(pTask->pLogData);
    PMDFreeMemory(pTask);
    pModule->pCurrentTask = NULL;
}

void
rolemgmt_free_plugin_module_tasks(
    PPMD_PLUGIN_MODULE pModule
    )
{
    if(!pModule || !pModule->pCurrentTask)
    {
        return;
    }
    pthread_mutex_lock(&pModule->mutexTasks);

    rolemgmt_free_plugin_module_task(pModule);

    pthread_mutex_unlock(&pModule->mutexTasks);
}

void
rolemgmt_free_plugin_module(
    PPMD_PLUGIN_MODULE pModule
    )
{
    if(!pModule)
    {
        return;
    }

    pthread_mutex_lock(&pModule->mutexModule);

    rolemgmt_free_plugin_module_tasks(pModule);

    if(pModule->pFnUnload)
    {
        pModule->pFnUnload(pModule->pInterface);
        pModule->pFnUnload = NULL;
    }

    if(pModule->pHandle)
    {
        dlclose(pModule->pHandle);
        pModule->pHandle = NULL;
    }

    pthread_mutex_unlock(&pModule->mutexModule);

    PMDFreeMemory(pModule);
}

void
rolemgmt_free_context(
    PPMD_PLUGIN_CONTEXT pContext
    )
{
    if(!pContext)
    {
        return;
    }

    rolemgmt_free_plugin_module(pContext->pModule);
    PMD_SAFE_FREE_MEMORY(pContext->pszPluginId);
    PMD_SAFE_FREE_MEMORY(pContext->pszPluginPath);
    PMDFreeMemory(pContext);
}

void
rolemgmt_free_contexts(
    PPMD_PLUGIN_CONTEXT pContexts
    )
{
    if(!pContexts)
    {
        return;
    }
    while(pContexts)
    {
        PPMD_PLUGIN_CONTEXT pContext = pContexts->pNext;
        rolemgmt_free_context(pContexts);
        pContexts = pContext;
    }
}
