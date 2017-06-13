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

REST_MODULE _pmd_rest_module[] =
{
    {
        "/v1/javelin.json",
        {pmd_rest_api_spec, NULL, NULL, NULL}
    },
    {
        "/v1/info",
        {pmd_rest_server_info, NULL, NULL, NULL}
    },
    {0}
};

uint32_t
pmd_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _pmd_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_rest_api_spec(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = file_read_all_text(
                  gpServerEnv->pConfig->pRestConfig->pszApiSpec,
                  &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
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
pmd_rest_get_sysinfo_json(
    json_t **ppSysInfo
    )
{
    uint32_t dwError = 0;
    json_t *pSysInfo = NULL;
    struct sysinfo stInfo = {0};

    dwError = sysinfo(&stInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pSysInfo = json_object();
    if(!pSysInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pSysInfo,
                                  "uptime",
                                  json_integer(stInfo.uptime));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pSysInfo,
                                  "procs",
                                  json_integer(stInfo.procs));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pSysInfo,
                                  "totalram",
                                  json_integer(stInfo.totalram));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pSysInfo,
                                  "freeram",
                                  json_integer(stInfo.freeram));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppSysInfo = pSysInfo;

cleanup:
    return dwError;

error:
    if(pSysInfo)
    {
        json_decref(pSysInfo);
    }
    goto cleanup;
}

uint32_t
pmd_rest_get_uname_json(
    json_t **ppUname
    )
{
    uint32_t dwError = 0;
    json_t *pUname = NULL;
    struct utsname stUname = {0};

    dwError = uname(&stUname);
    BAIL_ON_PMD_ERROR(dwError);

    pUname = json_object();
    if(!pUname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pUname,
                                  "sysname",
                                  json_string(stUname.sysname));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pUname,
                                  "nodename",
                                  json_string(stUname.nodename));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pUname,
                                  "release",
                                  json_string(stUname.release));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pUname,
                                  "version",
                                  json_string(stUname.version));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_object_set_new(pUname,
                                  "machine",
                                  json_string(stUname.machine));
    if(dwError)
    {
        dwError = ERROR_PMD_JSON_SET_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppUname = pUname;

cleanup:
    return dwError;

error:
    if(pUname)
    {
        json_decref(pUname);
    }
    goto cleanup;
}

uint32_t
pmd_rest_server_info(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    json_t *pRoot = NULL;
    json_t *pSysInfo = NULL;
    json_t *pUname = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_object();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_rest_get_sysinfo_json(&pSysInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pmd_rest_get_uname_json(&pUname);
    BAIL_ON_PMD_ERROR(dwError);

    json_object_set_new(pRoot, "sysinfo", pSysInfo);
    json_object_set_new(pRoot, "uname", pUname);

    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

