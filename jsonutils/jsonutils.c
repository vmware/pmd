/*
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

void
show_json_error(
    json_error_t *pError
    )
{
    if(!pError)
    {
        return;
    }
    fprintf(stderr, "error reading apispec: \n line: %d\n error: %s\n",
            pError->line,
            pError->text);
}

uint32_t
get_json_object_from_string(
    const char *pszString,
    json_t **ppJsonObject
    )
{
    uint32_t dwError = 0;
    json_t *pObject = NULL;
    json_error_t stError = {0};

    if(IsNullOrEmptyString(pszString) || !ppJsonObject)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pObject = json_loads(pszString, 0, &stError);
    if(!pObject)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppJsonObject = pObject;

cleanup:
    return dwError;

error:
    show_json_error(&stError);
    goto cleanup;
}

uint32_t
get_json_object(
    PKEYVALUE pKeyValue,
    json_t **ppJsonObject
    )
{
    uint32_t dwError = 0;
    uint32_t dwIndex = 0;
    json_t *root = NULL;

    if(!pKeyValue || !ppJsonObject)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    root = json_object();
    if(!root)
    {
        dwError = ENOMEM;
        BAIL_ON_PMD_ERROR(dwError);
    }

    while(pKeyValue)
    {
        dwError = json_object_set_new(
                      root,
                      pKeyValue->pszKey,
                      json_string(pKeyValue->pszValue));
        if(dwError)
        {
            dwError = ERROR_PMD_JSON_SET_VALUE;
            BAIL_ON_PMD_ERROR(dwError);
        }
        pKeyValue = pKeyValue->pNext;
    }

    *ppJsonObject = root;

cleanup:
    return dwError;

error:
    if(root)
    {
        json_decref(root);
    }
    goto cleanup;
}

uint32_t
get_json_string(
    PKEYVALUE pKeyValue,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJsonString = NULL;
    char *pszJson = NULL;
    json_t *pJson = NULL;

    if(!pKeyValue || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object(pKeyValue, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    pszJsonString = json_dumps(pJson, 0);
    if(!pszJsonString)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszJsonString, &pszJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszJson = pszJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszJsonString);
    if(pJson)
    {
        json_decref(pJson);
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
make_keyvalue(
    const char* pszKey,
    const char* pszValue,
    PKEYVALUE *ppKeyValue
    )
{
    uint32_t dwError = 0;
    PKEYVALUE pKeyValue = NULL;

    if(!ppKeyValue)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(KEYVALUE), (void **)&pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    if(pszKey)
    {
        dwError = PMDAllocateString(pszKey, &pKeyValue->pszKey);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszValue)
    {
        dwError = PMDAllocateString(pszValue, &pKeyValue->pszValue);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppKeyValue = pKeyValue;
cleanup:
    return dwError;

error:
    if(ppKeyValue)
    {
        *ppKeyValue = NULL;
    }
    if(pKeyValue)
    {
        free_keyvalue(pKeyValue);
    }
    goto cleanup;
}

void
free_keyvalue(
    PKEYVALUE pKeyValue
    )
{
    PKEYVALUE pCur = pKeyValue;
    while(pCur)
    {
       pKeyValue = pCur->pNext;

       PMD_SAFE_FREE_MEMORY(pCur->pszKey);
       PMD_SAFE_FREE_MEMORY(pCur->pszValue);
       PMD_SAFE_FREE_MEMORY(pCur);

       pCur = pKeyValue;
    }
}

uint32_t
json_get_opt_string_value(
    json_t *pRoot,
    const char *pszKey,
    char **ppszValue
    )
{
    uint32_t dwError = json_get_string_value(pRoot, pszKey, ppszValue);
    if(dwError == ENOENT)
    {
        dwError = 0;
    }
    return dwError;
}

uint32_t
json_get_string_value(
    json_t *pRoot,
    const char *pszKey,
    char **ppszValue
    )
{
    uint32_t dwError = 0;
    json_t *pJson = NULL;
    char *pszValue = NULL;

    if(!pRoot || !pszKey || !ppszValue)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pJson = json_object_get(pRoot, pszKey);
    if(!pJson)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(json_string_value(pJson), &pszValue);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszValue = pszValue;

cleanup:
    return dwError;

error:
    if(ppszValue)
    {
        *ppszValue = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszValue);
    goto cleanup;
}

uint32_t
json_get_string_array(
    json_t *pJson,
    const char *pszKey,
    int *pnCount,
    char ***pppszValues
    )
{
    uint32_t dwError = 0;
    char **ppszValues = NULL;
    char *pszValues = NULL;
    char *pszCommaSepValues = NULL;
    int nCount = 0;

    if(!pJson || IsNullOrEmptyString(pszKey) || !pnCount || !pppszValues)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_get_string_value(pJson, pszKey, &pszValues);
    BAIL_ON_PMD_ERROR(dwError);

    if (!IsNullOrEmptyString(pszValues))
    {
        dwError = string_replace(pszValues,
                                 REST_COMMA,
                                 ",",
                                 &pszCommaSepValues);
        if(dwError == ENOENT)
        {
            dwError = PMDAllocateString(pszValues, &pszCommaSepValues);
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = make_array_from_string(pszCommaSepValues,
                                         ",",
                                         &ppszValues,
                                         (int *)&nCount);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pnCount = nCount;
    *pppszValues = ppszValues;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszValues);
    PMD_SAFE_FREE_MEMORY(pszCommaSepValues);
    return dwError;

error:
    if(pnCount)
    {
        *pnCount = 0;
    }
    if(pppszValues)
    {
        *pppszValues = NULL;
    }
    PMDFreeStringArrayWithCount(ppszValues, nCount);
    goto cleanup;
}

uint32_t
json_make_result_success(
    char **ppszOutput
    )
{
    uint32_t dwError = 0;
    char *pszOutput = NULL;

    if(!ppszOutput)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_string_from_key_value("result", "success", &pszOutput);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutput = pszOutput;
cleanup:
    return dwError;

error:
    if(ppszOutput)
    {
        *ppszOutput = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutput);
    goto cleanup;
}

uint32_t
json_string_from_key_value(
    const char *pszKey,
    const char *pszValue,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;

    if(IsNullOrEmptyString(pszKey) ||
       IsNullOrEmptyString(pszValue) ||
       !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_object();
    if(!pRoot)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pRoot, pszKey, json_string(pszValue));
    BAIL_ON_PMD_ERROR(dwError);

    pszJson = json_dumps(pRoot, 0);
    if(IsNullOrEmptyString(pszJson))
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

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
    if(pszJson)
    {
        json_free_t(pszJson);
    }
    goto cleanup;
}
