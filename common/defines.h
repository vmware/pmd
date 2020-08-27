/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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
#define INVALID_CMD_CHARS ";&|`"
#define IsNullOrEmptyString(str) (!(str) || !(*str))
typedef unsigned short int  wchar16_t;
#define DO_RPC(rpc_pfn, sts) \
  do {                       \
    dcethread_exc *exc = NULL;      \
    DCETHREAD_TRY            \
    {                        \
      (sts) = rpc_pfn;       \
    }                        \
    DCETHREAD_CATCH_ALL(exc) \
    {                        \
      sts = dcethread_exc_getstatus(exc); \
    }                        \
    DCETHREAD_ENDTRY         \
  } while (0)

#define PPMD_RPC_PROTECT_LEVEL_NONE        rpc_c_protect_level_none
#define BAIL_ON_PMD_ERROR(dwError) \
    do {                                                           \
        if (dwError)                                               \
        {                                                          \
            goto error;                                            \
        }                                                          \
    } while(0)

#define BAIL_ON_PMD_SYSTEM_ERROR(dwError) \
    do {                                                           \
        if (dwError)                                               \
        {                                                          \
            dwError = ERROR_PMD_SYSTEM_BASE + dwError;             \
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
    {ERROR_PMD_BASE,                  "ERROR_PMD_EBASE",                  "Generic base error"}, \
    {ERROR_PMD_CONF_FILE_LOAD,        "ERROR_PMD_CONF_FILE_LOAD",         "Error reading config file."}, \
    {ERROR_PMD_INVALID_DAEMON_USER,   "ERROR_PMD_INVALID_DAEMON_USER",    "Could not verify server integrity for this communication. Cannot proceed."}, \
    {ERROR_PMD_RPC_PEER_NOT_READY,    "ERROR_PMD_RPC_PEER_NOT_READY",     "rpc connection not established."}, \
    {ERROR_PMD_PRIVSEP_INTEGRITY,     "ERROR_PMD_PRIVSEP_INTEGRITY",      "Unable to verify privilege separation integrity. Cannot proceed."}, \
    {ERROR_PMD_MISSING_PRIVSEP_PUBKEY,"ERROR_PMD_MISSING_PRIVSEP_PUBKEY", "Missing public key for privilege separation encryption. Please check config."}, \
    {ERROR_PMD_PRIVSEP_ENCRYPT,       "ERROR_PMD_PRIVSEP_ENCRYPT",        "There was an error encrypting information for privilege separation. Please check privilege separation keys."}, \
    {ERROR_PMD_PRIVSEP_DECRYPT,       "ERROR_PMD_PRIVSEP_DECRYPT",        "There was an error decrypting information for privilege separation. Please check privilege separation keys."}, \
    {ERROR_PMD_INVALID_CMD,           "ERROR_PMD_INVALID_CMD",            "Invalid command."}, \
    {ERROR_PMD_NOTHING_TO_DO,         "ERROR_PMD_NOTHING_TO_DO",          "Nothing to do."}, \
    {ERROR_PMD_ROLES_PLUGIN_NOT_SET,  "ERROR_PMD_ROLES_PLUGIN_NOT_SET",   "Plugin is not set for this role."}, \
    {ERROR_PMD_ROLE_UNMAPPED_FN,      "ERROR_PMD_ROLE_UNMAPPED_FN",       "Plugin is loaded but does not specify an entry point for this functionality."}, \
    {ERROR_PMD_ROLE_UNMAPPED_LOAD,    "ERROR_PMD_ROLE_UNMAPPED_LOAD",     "Plugin is loaded but does not specify an entry point for javelin_role_load."}, \
    {ERROR_PMD_ROLE_PLUGIN_BAD,       "ERROR_PMD_ROLE_PLUGIN_BAD",        "Plugin is loaded but did not behave as expected. Plugin has been disabled for this session."}, \
    {ERROR_PMD_ROLE_PLUGIN_DISABLED,  "ERROR_PMD_ROLE_PLUGIN_DISABLED",   "Plugin is disabled. Most likely cause is an unexpected response from plugin apis. Restarting the server will reload plugins."}, \
    {ERROR_PMD_ROLE_PLUGIN_HAS_TASKS, "ERROR_PMD_ROLE_PLUGIN_HAS_TASKS",  "Plugin has tasks. Please use status to get a status on tasks. Cannot queue another task at this time."}, \
    {ERROR_PMD_ROLE_TASK_NOT_FOUND,   "ERROR_PMD_ROLE_TASK_NOT_FOUND",    "Could not find a task matching the id provided."}, \
    {ERROR_PMD_ROLE_TASK_NO_LOGS,     "ERROR_PMD_ROLE_TASK_NO_LOGS",      "Task has no logs."}, \
    {ERROR_PMD_STRING_COMPARE_FAILED, "ERROR_PMD_STRING_COMPARE_FAILED",  "String comparison failed."}, \
    {ERROR_PMD_CONVERT_TO_WCHAR_FAILED, "ERROR_PMD_CONVERT_TO_WCHAR_FAILED", "String conversion Failed."}, \
};
