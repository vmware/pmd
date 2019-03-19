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

REST_MODULE _rolemgmt_rest_module[] =
{
    {
        "/v1/rolemgmt/version",
        {
            rolemgmt_rest_get_version,
            NULL,
            NULL,
            NULL
        }
    },
    {
        "/v1/rolemgmt/role/version",
        {
            rolemgmt_rest_get_roleversion,
            NULL,
            NULL,
            NULL
        }
    },
    {
        "/v1/rolemgmt/roles",
        {
            rolemgmt_rest_get_roles,
            NULL,
            NULL,
            NULL
        }
    },
    {
        "/v1/rolemgmt/role/status",
        {
            rolemgmt_rest_get_status,
            NULL,
            NULL,
            NULL
        }
    },
    {
        "/v1/rolemgmt/role/logs",
        {
            rolemgmt_rest_get_logs,
            NULL,
            NULL,
            NULL
        }
    },
    {
        "/v1/rolemgmt/role/alter",
        {
            NULL,
            rolemgmt_rest_alter_put,
            NULL,
            rolemgmt_rest_alter_delete,
            rolemgmt_rest_alter_patch
        }
    },
    {0}
};

uint32_t
rolemgmt_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _rolemgmt_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_rest_get_version(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    char *pszOutputJson = NULL;
    PKEYVALUE pKeyValue = NULL;

    if(!ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rolemgmt_get_version(&pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("version", pszVersion, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
rolemgmt_rest_get_roleversion(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    char *pszVersion = NULL;
    char *pszOutputJson = NULL;
    PKEYVALUE pKeyValue = NULL;
    const char *pszInputJson = pInputJson;
    json_t *pJson = NULL;
    if(!pszInputJson || !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rolemgmt_get_version(&pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "name", &pszName);

    dwError = pmd_rolemgmt_role_version(pszName, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("version", pszVersion, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
get_tasklogs_json(
    int nCount,
    PPMD_PLUGIN_TASK_LOG pTaskLogs,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    int i = 0;

    if(!pTaskLogs || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(; pTaskLogs && i < nCount; pTaskLogs = pTaskLogs->pNext, ++i)
    {
        json_t *pLogObj = json_object();
        json_object_set_new(pLogObj, "log", json_string(pTaskLogs->pszLog));
        json_array_append_new(pRoot, pLogObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}


uint32_t
get_roles_json_string(
    PPMD_ROLEMGMT_ROLE pRoles,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;

    if(!pRoles || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pRole = pRoles; pRole; pRole = pRole->pNext)
    {
        json_t *pRoleObj = json_object();
        json_object_set_new(pRoleObj, "id", json_string(pRole->pszId));
        json_object_set_new(pRoleObj, "name", json_string(pRole->pszName));
        json_object_set_new(pRoleObj, "baseurl", json_string(pRole->pszDescription));
        json_array_append_new(pRoot, pRoleObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
rolemgmt_rest_get_roles(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    int nLocked = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;

    if(!ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pthread_mutex_lock(&gRoleMgmtEnv.mutexEnv);
    nLocked = 1;

    pRoles = gRoleMgmtEnv.pRoles;
    if(!pRoles)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_roles_json_string(pRoles, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    if(nLocked)
    {
        pthread_mutex_unlock(&gRoleMgmtEnv.mutexEnv);
    }
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
rolemgmt_rest_get_status(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszName = NULL;
    char *pszTaskUUID = NULL;
    char *pszOutputJson = NULL;
    char *pszStatus = NULL;
    json_t *pJson = NULL;
    PMD_ROLE_STATUS nStatus = ROLE_STATUS_NONE;
    PKEYVALUE pKeyValue = NULL;
    char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "name", &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "taskid", &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_get_status(pszName, pszTaskUUID, &nStatus);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("status", pszStatus, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszName);
    PMD_SAFE_FREE_MEMORY(pszTaskUUID);
    PMD_SAFE_FREE_MEMORY(pszStatus);
    free_keyvalue(pKeyValue);
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
rolemgmt_rest_get_logs(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszTaskUUID = NULL;
    char *pszOutputJson = NULL;
    char *pszStartAt = NULL;
    char *pszCount = NULL;
    char *pszStatus = NULL;
    json_t *pJson = NULL;
    char *pszInputJson = pInputJson;
    int nStartAt = 0;
    int nCount = 0;
    PPMD_PLUGIN_TASK_LOG pTaskLogs = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "taskid", &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "startat", &pszStartAt);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "count", &pszCount);
    BAIL_ON_PMD_ERROR(dwError);

    nStartAt = atoi(pszStartAt);
    nCount = atoi(pszCount);

    dwError = pmd_rolemgmt_get_logs(
                  pszTaskUUID,
                  nStartAt,
                  nCount,
                  &pTaskLogs);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_tasklogs_json(nCount, pTaskLogs, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszTaskUUID);
    PMD_SAFE_FREE_MEMORY(pszStartAt);
    PMD_SAFE_FREE_MEMORY(pszCount);
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
rolemgmt_rest_do_alter(
    PMD_ROLE_OPERATION nOperation,
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszTaskUUID = NULL;
    char *pszOutputJson = NULL;
    char *pszConfig = NULL;
    char *pszName = NULL;
    json_t *pJson = NULL;
    char *pszInputJson = pInputJson;
    PKEYVALUE pKeyValue = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "name", &pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "config", &pszConfig);
    if(nOperation != ROLE_OPERATION_ENABLE && !pszConfig)
    {
        dwError = PMDAllocateString("{}", &pszConfig);
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rolemgmt_role_alter(
                  pszName,
                  nOperation,
                  pszConfig,
                  &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("taskid", pszTaskUUID, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    PMD_SAFE_FREE_MEMORY(pszConfig);
    PMD_SAFE_FREE_MEMORY(pszTaskUUID);
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}
uint32_t
rolemgmt_rest_alter_put(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    return rolemgmt_rest_do_alter(
               ROLE_OPERATION_ENABLE,
               pInputJson,
               ppszOutputJson);
}

uint32_t
rolemgmt_rest_alter_delete(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    return rolemgmt_rest_do_alter(
               ROLE_OPERATION_REMOVE,
               pInputJson,
               ppszOutputJson);
}

uint32_t
rolemgmt_rest_alter_patch(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    return rolemgmt_rest_do_alter(
               ROLE_OPERATION_UPDATE,
               pInputJson,
               ppszOutputJson);
}

