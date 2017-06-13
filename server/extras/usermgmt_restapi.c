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

REST_MODULE _usrmgmt_rest_module[] =
{
    {
        "/v1/usrmgmt/users",
        {usrmgmt_rest_get_users, NULL, NULL, NULL}
    },
    {
        "/v1/usrmgmt/userid",
        {usrmgmt_rest_get_userid, NULL, NULL, NULL}
    },
    {
        "/v1/usrmgmt/useradd",
        {NULL, usrmgmt_rest_put_user, NULL, NULL}
    },
    {
        "/v1/usrmgmt/userdel",
        {NULL, NULL, NULL, usrmgmt_rest_delete_user}
    },
    {
        "/v1/usrmgmt/groups",
        {usrmgmt_rest_get_groups, NULL, NULL, NULL}
    },
    {
        "/v1/usrmgmt/groupid",
        {usrmgmt_rest_get_groupid, NULL, NULL, NULL}
    },
    {
        "/v1/usrmgmt/groupadd",
        {NULL, usrmgmt_rest_put_group, NULL, NULL}
    },
    {
        "/v1/usrmgmt/groupdel",
        {NULL, NULL, NULL, usrmgmt_rest_delete_group}
    },
    {0}
};

uint32_t
usrmgmt_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _usrmgmt_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
get_users_json_string(
    PPMD_USER pUser,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;

    if(!pUser || !ppszJson)
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

    for(; pUser; pUser = pUser->pNext)
    {
        json_t *pUserObj = json_object();
        json_object_set_new(pUserObj, "name", json_string(pUser->pszName));
        json_object_set_new(pUserObj, "userid", json_integer(pUser->nUID));
        json_object_set_new(pUserObj, "groupid", json_integer(pUser->nGID));
        json_object_set_new(pUserObj, "description", json_string(pUser->pszRealName));
        json_object_set_new(pUserObj, "homedir", json_string(pUser->pszHomeDir));
        json_object_set_new(pUserObj, "shell", json_string(pUser->pszShell));
        json_array_append_new(pRoot, pUserObj);
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
usrmgmt_rest_get_users(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    PPMD_USER pUsers = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_get_users(&pUsers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_users_json_string(pUsers, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    usermgmt_free_user(pUsers);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
usrmgmt_rest_get_userid(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    uint32_t nUID = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    char *pszName = NULL;
    PKEYVALUE pKeyValue = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "name", &pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_get_userid(pszName, &nUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("userid", NULL, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pKeyValue->pszValue, "%d", nUID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_free_t(pJson);
    }
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
usrmgmt_rest_put_user(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    char *pszName = NULL;
    PKEYVALUE pKeyValue = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "name", &pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_add_user(pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("result", "success", &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_free_t(pJson);
    }
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
usrmgmt_rest_delete_user(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    char *pszName = NULL;
    PKEYVALUE pKeyValue = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "name", &pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_delete_user(pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("result", "success", &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_free_t(pJson);
    }
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
get_groups_json_string(
    PPMD_GROUP pGroup,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;

    if(!pGroup || !ppszJson)
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

    for(; pGroup; pGroup = pGroup->pNext)
    {
        json_t *pGroupObj = json_object();
        json_object_set_new(pGroupObj, "name", json_string(pGroup->pszName));
        json_object_set_new(pGroupObj, "groupid", json_integer(pGroup->nGID));
        json_array_append_new(pRoot, pGroupObj);
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
usrmgmt_rest_get_groups(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    PPMD_GROUP pGroups = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_get_groups(&pGroups);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_groups_json_string(pGroups, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    usermgmt_free_group(pGroups);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
usrmgmt_rest_get_groupid(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    uint32_t nGID = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    char *pszName = NULL;
    PKEYVALUE pKeyValue = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "name", &pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_get_groupid(pszName, &nGID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("groupid", NULL, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pKeyValue->pszValue, "%d", nGID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_free_t(pJson);
    }
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
usrmgmt_rest_delete_group(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    char *pszName = NULL;
    PKEYVALUE pKeyValue = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "name", &pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_delete_group(pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("result", "success", &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_free_t(pJson);
    }
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
usrmgmt_rest_put_group(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    char *pszName = NULL;
    PKEYVALUE pKeyValue = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszInputJson)
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "name", &pszName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_usermgmt_add_group(pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("result", "success", &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_free_t(pJson);
    }
    free_keyvalue(pKeyValue);
    PMD_SAFE_FREE_MEMORY(pszName);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}
