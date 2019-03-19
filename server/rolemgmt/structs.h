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

#pragma once

typedef struct _PMD_CONFIG_ITEM_
{
    char *pszId;
    char *pszName;
    char *pszDisplayName;
    char *pszDescription;
    char *pszParent;
    char *pszPlugin;
    struct _PMD_CONFIG_ITEM_ *pNext;
}PMD_CONFIG_ITEM, *PPMD_CONFIG_ITEM;

typedef struct _PMD_PLUGIN_TASK_LOG_
{
    time_t tStamp;
    char *pszLog;
    struct _PMD_PLUGIN_TASK_LOG_ *pNext;
}PMD_PLUGIN_TASK_LOG, *PPMD_PLUGIN_TASK_LOG;

typedef struct _PMD_PLUGIN_TASK_
{
    pthread_t nThreadID;
    char *pszTaskUUID;
    PMD_ROLE_STATUS nStatus;
    uint32_t dwError;
    time_t tStart;
    PPMD_ROLE_HANDLE pRoleHandle;
    PMD_ROLE_OPERATION nOperation;
    char *pszConfigJson;
    PFN_ALTER_PROGRESS_CALLBACK pFnProgressCallback;
    PPMD_PLUGIN_TASK_LOG pLogData;

    struct _PMD_PLUGIN_TASK_ *pNext;
}PMD_PLUGIN_TASK, *PPMD_PLUGIN_TASK;

typedef struct _PMD_PLUGIN_MODULE_
{
    int nDisabled;
    pthread_mutex_t mutexModule;
    //dlopen handle
    void *pHandle;

    //Tasks
    pthread_mutex_t mutexTasks;
    PPMD_PLUGIN_TASK pCurrentTask;
    PPMD_PLUGIN_TASK pTaskHistory;

    //Mandatory entry point
    PFN_PMD_ROLEPLUGIN_LOAD_INTERFACE pFnLoad;
    //Optional unload
    PFN_PMD_ROLEPLUGIN_UNLOAD_INTERFACE pFnUnload;

    //interface fn table returned by load.
    PPMD_ROLE_PLUGIN_INTERFACE pInterface;
}PMD_PLUGIN_MODULE, *PPMD_PLUGIN_MODULE;

typedef struct _PMD_PLUGIN_TASK_THREAD_INFO_
{
    PPMD_PLUGIN_MODULE pModule;
    PPMD_PLUGIN_TASK pTask;
}PMD_PLUGIN_TASK_THREAD_INFO,*PPMD_PLUGIN_TASK_THREAD_INFO;

typedef struct _PMD_PLUGIN_CONTEXT_
{
    char *pszPluginId;
    char *pszPluginPath;
    PPMD_PLUGIN_MODULE pModule;

    struct _PMD_PLUGIN_CONTEXT_ *pNext;
}PMD_PLUGIN_CONTEXT, *PPMD_PLUGIN_CONTEXT;

typedef struct _PMD_ROLEMGMT_ENV_
{
    pthread_mutex_t mutexEnv;
    PPMD_PLUGIN_CONTEXT pContexts;
    PPMD_ROLEMGMT_ROLE pRoles;
}PMD_ROLEMGMT_ENV, *PPMD_ROLEMGMT_ENV;
