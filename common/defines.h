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

#pragma once

#ifndef PMD_WSTRING_DEFINED
typedef unsigned short* wstring_t;
#endif

#define MAX_LINE_LENGTH 1024
#define MAX_CONFIG_LINE_LENGTH 1024

#define IsNullOrEmptyString(str) (!(str) || !(*str))

#define BAIL_ON_PMD_ERROR(dwError) \
    do {                                                           \
        if (dwError)                                               \
        {                                                          \
            goto error;                                            \
        }                                                          \
    } while(0)

#define PMD_SAFE_FREE_MEMORY(pMemory) \
    do {                                                           \
        if (pMemory) {                                             \
            PMDFreeMemory(pMemory);                                \
        }                                                          \
    } while(0)

#define PMD_RPCSRV_SAFE_FREE_MEMORY(pMemory) \
    do {                                                           \
        if (pMemory) {                                             \
            PMDRpcServerFreeMemory(pMemory);                                \
        }                                                          \
    } while(0)

#define PMD_UNKNOWN_ERROR_STRING "Unknown error"
#define PMD_ERROR_TABLE \
{ \
    {ERROR_PMD_BASE,                "ERROR_PMD_EBASE",               "Generic base error"}, \
    {ERROR_PMD_CONF_FILE_LOAD,      "ERROR_PMD_CONF_FILE_LOAD",      "Error reading config file."}, \
    {ERROR_PMD_NOTHING_TO_DO,       "ERROR_PMD_NOTHING_TO_DO",       "Nothing to do."}, \
    {ERROR_PMD_CONF_FILE_LOAD,      "ERROR_PMD_CONF_FILE_LOAD",      "Error reading config file."}, \
    {ERROR_PMD_ROLES_PLUGIN_NOT_SET,"ERROR_PMD_ROLES_PLUGIN_NOT_SET","Plugin is not set for this role."}, \
    {ERROR_PMD_ROLE_UNMAPPED_FN,    "ERROR_PMD_ROLE_UNMAPPED_FN",    "Plugin is loaded but does not specify an entry point for this functionality."}, \
    {ERROR_PMD_ROLE_UNMAPPED_LOAD,  "ERROR_PMD_ROLE_UNMAPPED_LOAD",  "Plugin is loaded but does not specify an entry point for javelin_role_load."}, \
    {ERROR_PMD_ROLE_PLUGIN_BAD,     "ERROR_PMD_ROLE_PLUGIN_BAD",     "Plugin is loaded but did not behave as expected. Plugin has been disabled for this session."}, \
    {ERROR_PMD_ROLE_PLUGIN_DISABLED,"ERROR_PMD_ROLE_PLUGIN_DISABLED","Plugin is disabled. Most likely cause is an unexpected response from plugin apis. Restarting the server will reload plugins."}, \
    {ERROR_PMD_ROLE_PLUGIN_HAS_TASKS,"ERROR_PMD_ROLE_PLUGIN_HAS_TASKS","Plugin has tasks. Please use status to get a status on tasks. Cannot queue another task at this time."}, \
    {ERROR_PMD_ROLE_TASK_NOT_FOUND,  "ERROR_PMD_ROLE_TASK_NOT_FOUND",  "Could not find a task matching the id provided."}, \
    {ERROR_PMD_ROLE_TASK_NO_LOGS,    "ERROR_PMD_ROLE_TASK_NO_LOGS",    "Task has no logs."}, \
};
