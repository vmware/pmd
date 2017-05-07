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

REST_MODULE _firewall_rest_module[] =
{
    {
        "/v1/firewall/version",
        {
            firewall_rest_get_version,
            NULL,
            NULL,
            NULL
        }
    },
    {
        "/v1/firewall/rules",
        {
            firewall_rest_get_rules,
            firewall_rest_put_rules,
            NULL,
            firewall_rest_delete_rules
        }
    },
    {
        "/v1/firewall/rules6",
        {
            firewall_rest_get_rules6,
            NULL,//firewall_rest_put_rules,
            NULL,
            NULL//firewall_rest_delete_rules
        }
    },
    {0}
};

uint32_t
firewall_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _firewall_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
firewall_rest_get_version(
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

    dwError = make_keyvalue("version", FIREWALL_API_VERSION, &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
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
get_firewall_json_string(
    PPMD_FIREWALL_RULE pRules,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;

    if(!pRules || !ppszJson)
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

    for(; pRules; pRules = pRules->pNext)
    {
        json_t *pRuleObj = json_object();
        json_object_set_new(pRuleObj, "rule", json_string(pRules->pszRule));
        json_array_append_new(pRoot, pRuleObj);
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
firewall_rest_get_rules(
    void *pszInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    PPMD_FIREWALL_RULE pRules = NULL;
    int nIPV6 = 0;

    if(!ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_firewall_get_rules(nIPV6, &pRules);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_firewall_json_string(pRules, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    fwmgmt_free_rules(pRules);
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
firewall_rest_put_rules(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    PPMD_FIREWALL_RULE pRules = NULL;
    PKEYVALUE pKeyValue = NULL;
    int nIPV6 = 0;
    int nPersist = 0;
    char *pszChain = NULL;
    char *pszRuleEncoded = NULL;
    char *pszRule = NULL;
    char *pszPersist = NULL;
    json_t *pJson = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "chain", &pszChain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "rule", &pszRuleEncoded);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = url_decode(pszRuleEncoded, &pszRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pJson, "persist", &pszPersist);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_add_rules(nIPV6, nPersist, pszChain, pszRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("result", "success", &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszChain);
    PMD_SAFE_FREE_MEMORY(pszRuleEncoded);
    PMD_SAFE_FREE_MEMORY(pszRule);
    PMD_SAFE_FREE_MEMORY(pszPersist);
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
firewall_rest_delete_rules(
    void *pInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    const char *pszInputJson = pInputJson;
    char *pszOutputJson = NULL;
    PPMD_FIREWALL_RULE pRules = NULL;
    PKEYVALUE pKeyValue = NULL;
    int nIPV6 = 0;
    int nPersist = 0;
    char *pszChain = NULL;
    char *pszRuleEncoded = NULL;
    char *pszRule = NULL;
    char *pszPersist = NULL;
    json_t *pJson = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "chain", &pszChain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "rule", &pszRuleEncoded);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = url_decode(pszRuleEncoded, &pszRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pJson, "persist", &pszPersist);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_firewall_delete_rules(nIPV6, nPersist, pszChain, pszRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_keyvalue("result", "success", &pKeyValue);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_json_string(pKeyValue, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszChain);
    PMD_SAFE_FREE_MEMORY(pszRuleEncoded);
    PMD_SAFE_FREE_MEMORY(pszRule);
    PMD_SAFE_FREE_MEMORY(pszPersist);
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
firewall_rest_get_rules6(
    void *pszInputJson,
    void **ppszOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    PPMD_FIREWALL_RULE pRules = NULL;
    int nIPV6 = 1;

    if(!ppszOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_firewall_get_rules(nIPV6, &pRules);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_firewall_json_string(pRules, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutputJson = pszOutputJson;

cleanup:
    fwmgmt_free_rules(pRules);
    return dwError;

error:
    if(ppszOutputJson)
    {
        *ppszOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}
