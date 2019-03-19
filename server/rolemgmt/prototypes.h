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

//rolemgmt_api.c - server api
uint32_t
pmd_rolemgmt_get_version(
    char **ppszVersion
    );

uint32_t
pmd_rolemgmt_get_roles(
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

uint32_t
pmd_rolemgmt_role_version(
    const char *pszName,
    char **ppszVersion
    );

uint32_t
pmd_rolemgmt_role_alter(
    const char *pszName,
    PMD_ROLE_OPERATION nOperation,
    const char *pszConfigJson,
    char **ppszTaskUUID
    );

uint32_t
pmd_rolemgmt_role_get_prereqs(
    const char *pszName,
    PMD_ROLE_OPERATION nOperation,
    PPMD_ROLE_PREREQ *ppPreReqs,
    uint32_t *pdwPreReqCount
    );

uint32_t
pmd_rolemgmt_alter_task_progress(
    const char *pszTaskUUID,
    const char *pszProgress
    );

uint32_t
pmd_rolemgmt_get_status(
    const char *pszName,
    const char *pszTaskUUID,
    PMD_ROLE_STATUS *pnStatus
    );

uint32_t
pmd_rolemgmt_get_logs(
    const char *pszTaskUUID,
    uint32_t dwOffset,
    uint32_t dwEntriesToFetch,
    PPMD_PLUGIN_TASK_LOG *ppTaskLogs
    );

uint32_t
rolemgmt_find_task_by_id(
    const char *pszTaskUUID,
    PPMD_PLUGIN_TASK *ppTask
    );

uint32_t
rolemgmt_find_archived_task_by_id(
    const char *pszTaskUUID,
    PPMD_PLUGIN_TASK *ppTask
    );	
void
rolemgmt_free_plugin_task_logs(
    PPMD_PLUGIN_TASK_LOG pLogs
    );

void
rolemgmt_free_plugin_module_task(
    PPMD_PLUGIN_MODULE pModule
    );

void
rolemgmt_free_plugin_module_tasks(
    PPMD_PLUGIN_MODULE pModule
    );

void
rolemgmt_free_context(
    PPMD_PLUGIN_CONTEXT pContext
    );

void
rolemgmt_free_contexts(
    PPMD_PLUGIN_CONTEXT pContexts
    );

//rolemgmt_rpcapi.c
void
rolemgmt_rpc_role_free_task_log_array(
    PPMD_RPC_ROLEMGMT_TASK_LOG_ARRAY pTaskLogArray
    );

void
rolemgmt_rpc_role_free_prereq_array(
    PPMD_RPC_ROLEMGMT_PREREQ_ARRAY pPrereqArray
    );

//rolemgmt_config.c

uint32_t
rolemgmt_load_roles(
    const char *pszRolesDir,
    const char *pszPluginsDir,
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

void
rolemgmt_free_role(
    PPMD_ROLEMGMT_ROLE pRole
    );

uint32_t
rolemgmt_move_role_children(
    PPMD_ROLEMGMT_ROLE pRole,
    PPMD_ROLEMGMT_ROLE *ppRoleArray,
    int nRoleCount
    );

uint32_t
rolemgmt_move_role_parents(
    PPMD_CONFIG_ITEM pItems,
    PPMD_ROLEMGMT_ROLE *ppRoleArray,
    int nRoleCount,
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

uint32_t
rolemgmt_copy_roles(
    PPMD_CONFIG_ITEM pItems,
    PPMD_ROLEMGMT_ROLE **ppRoles,
    int *pnRoleCount
    );

void
print_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    );

void
print_items(
    PPMD_CONFIG_ITEM pItems
    );

uint32_t
rolemgmt_read_roles(
    const char *pszRolesDir,
    PPMD_CONFIG_ITEM *ppItems
    );

uint32_t
rolemgmt_read_role(
    const char *pszFile,
    PPMD_CONFIG_ITEM *ppItems
    );

uint32_t
rolemgmt_load_item_data(
    PPMD_CONFIG_ITEM pRole,
    PCONF_SECTION pSection
    );

void
rolemgmt_free_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    );

void
rolemgmt_free_item(
    PPMD_CONFIG_ITEM pItem
    );

void
rolemgmt_free_items(
    PPMD_CONFIG_ITEM pItems
    );

//rolemgmt_plugin.c
uint32_t
pmd_rolemgmt_plugin_get_version(
    const PPMD_PLUGIN_MODULE pModule,
    char **ppszVersion
    );

uint32_t
pmd_rolemgmt_plugin_open(
    const PPMD_PLUGIN_MODULE pModule,
    PPMD_ROLE_HANDLE *ppRoleHandle
    );

uint32_t
pmd_rolemgmt_plugin_close(
    const PPMD_PLUGIN_MODULE pModule,
    PPMD_ROLE_HANDLE pRoleHandle
    );

uint32_t
pmd_rolemgmt_plugin_get_prereqs(
    const PPMD_PLUGIN_MODULE pModule,
    PMD_ROLE_OPERATION nOperation,
    const PPMD_ROLE_HANDLE pRoleHandle,
    PPMD_ROLE_PREREQ *ppPreReqs,
    uint32_t *pdwPreReqCount
    );

uint32_t
pmd_rolemgmt_plugin_alter(
    const PPMD_PLUGIN_MODULE pModule,
    const PPMD_PLUGIN_TASK pTask
    );
//rolemgmt_restapi.c
uint32_t
rolemgmt_rest_get_version(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_get_roleversion(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_get_roles(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_get_status(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_get_logs(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_alter(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_alter_put(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_alter_delete(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
rolemgmt_rest_alter_patch(
    void *pInputJson,
    void **ppszOutputJson
    );

