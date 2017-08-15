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

uint32_t
pmd_policy_plugin_load_interface()
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    char *pszGpmgmtPluginPath = NULL;
        //Test code for logs to be relocated
    char * pszGpmgmtSQLLogsPath = NULL;
    sqlite3 *pDb;
    PPMD_POLICY_LOG pLogEntry = NULL;
    uint32_t dwLogCount =0;
        // End of test code
    dlerror();
    dwError =PMDAllocateMemory(sizeof(PMD_POLICY_PLUGIN_INTERFACE),
                      (void **)&gpServerEnv->gpGroupInterface);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_val_from_file(PMD_CONFIG_FILE_NAME,
                                PMD_CONFIG_GP_GROUP,
                                PMD_CONFIG_KEY_GPMGMT_PLUGIN_PATH,
                                &pszGpmgmtPluginPath);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(stdout, "Loading gpmgmt plugin from path : %s \n", pszGpmgmtPluginPath);
    gpServerEnv->gpGroupInterface->hHandle = dlopen(pszGpmgmtPluginPath,
                                             RTLD_LAZY | RTLD_GLOBAL);

    if (!gpServerEnv->gpGroupInterface->hHandle)
    {
        fprintf(stderr, "\n Group policy library load failed %s\n", dlerror());
        dwError = ERROR_PMD_GPMGMT_PLUGIN_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpServerEnv->gpGroupInterface->pFnPolicyVersion = dlsym(
        gpServerEnv->gpGroupInterface->hHandle,
        "pmd_gpmgmt_get_version");
    if (!gpServerEnv->gpGroupInterface->pFnPolicyVersion)
    {
        fprintf(stderr, "\n Group policy symbol \"pmd_gpmgmt_get_version\" not found %s\n",
                                                                                dlerror());
        dwError = ERROR_PMD_GPMGMT_SYMBOL_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpServerEnv->gpGroupInterface->pFnStartPolicies = dlsym(
        gpServerEnv->gpGroupInterface->hHandle,
        "pmd_gpmgmt_start_policies");
    if (!gpServerEnv->gpGroupInterface->pFnStartPolicies)
    {
        fprintf(stderr, "\n Group policy symbol \"pmd_gpmgmt_start_policies\" not found %s\n",
                                                                                 dlerror());
        dwError = ERROR_PMD_GPMGMT_SYMBOL_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpServerEnv->gpGroupInterface->pFnStopPolicies = dlsym(
        gpServerEnv->gpGroupInterface->hHandle,
        "pmd_gpmgmt_stop_policies");
    if (!gpServerEnv->gpGroupInterface->pFnStopPolicies)
    {
        fprintf(stderr, "\n Group policy symbol \"pmd_gpmgmt_stop_policies\" not found %s\n",
                                                                                 dlerror());
        dwError = ERROR_PMD_GPMGMT_SYMBOL_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    gpServerEnv->gpGroupInterface->pFnPolicyVersion(&pszVersion);
    if (IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    fprintf(stdout, "Group policy version is %s\n", pszVersion);

    //Test code for logs to be relocated
        //Start a sql log  connection;
    dwError = get_val_from_file(PMD_CONFIG_FILE_NAME,
                                PMD_CONFIG_GP_GROUP,
                                PMD_CONFIG_KEY_GPMGMT_SQL_LOGS,
                                &pszGpmgmtSQLLogsPath);
    BAIL_ON_PMD_ERROR(dwError);
    fprintf(stdout, "Logs path is %s\n", pszGpmgmtSQLLogsPath);

   //Create the file and create a default file
    dwError = gpmgmt_sql_create_logs(
       pszGpmgmtSQLLogsPath,
       &pDb
        );
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(PMD_POLICY_LOG),(void **)&pLogEntry);
    BAIL_ON_PMD_ERROR(dwError);

    pLogEntry->pszIPAddress = "127.0.0.1";
    pLogEntry->pszTime = "15th Aug, 2017";
    pLogEntry->pszLogType = "127.0.0.1";
    pLogEntry->pszPolicyName = "updatepolicy";
    pLogEntry->pszIsSuccessful = "True";
    pLogEntry->pszErrorStr = "Sample Error";

    dwError = gpmgmt_sql_add_log(pDb,pLogEntry);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_query_all_logs(pDb,&pLogEntry,&dwLogCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_print_logs(pLogEntry);
    BAIL_ON_PMD_ERROR(dwError);

    gpmgmt_sql_database_close(pDb);

    gpmgmt_sql_free_log_entry(pLogEntry);
    //End of testcode for SQLlogs

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    PMD_SAFE_FREE_MEMORY(pszGpmgmtPluginPath);
    return dwError;

error:
    fprintf(stdout, "Error opening the policy interface:  Error(%d) \n\n",dwError);
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);
    goto cleanup;
}

uint32_t
pmd_policy_plugin_unload_interface()
{
    uint32_t dwError = 0;
    //Close the library
    if (gpServerEnv->gpGroupInterface->hHandle)
    {
        dwError = dlclose(gpServerEnv->gpGroupInterface->hHandle);
        if (dwError != 0)
        {
            dwError = ERROR_PMD_GPMGMT_PLUGIN_UNLOAD_FAILED;
            goto error;
        }
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(gpServerEnv->gpGroupInterface);
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_gpmgmt_load_policies(
    PPMD_POLICY_DATA *ppPolicies)
{
    uint32_t dwError = 0;
    PPMD_POLICY_DATA pPoliciesHead = NULL;
    PPMD_POLICY_DATA pPolicy = NULL;
    char *pszPolicyJsonPath = NULL;
    json_t *root = NULL;
    json_error_t error;
    const char *pKey = NULL;
    json_t *pValue = NULL;

    dwError = get_val_from_file(PMD_CONFIG_FILE_NAME,
                                PMD_CONFIG_GP_GROUP,
                                PMD_CONFIG_KEY_GP_POLICY_JSON,
                                &pszPolicyJsonPath);
    BAIL_ON_PMD_ERROR(dwError);

    root = json_load_file(pszPolicyJsonPath, 0, &error);
    if (!root)
    {
        dwError = ERROR_PMD_GPMGMT_CANNT_LOAD_JSON;
        fprintf(stderr, "Unable to load the policy json: %s at source: %s at line: %d \n",
                error.text, error.source, error.line);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!json_is_object(root))
    {
        dwError = ERROR_PMD_GPMGMT_CANNT_LOAD_JSON;
        BAIL_ON_PMD_ERROR(dwError);
    }

    json_object_foreach(root, pKey, pValue)
    {
        if (!pPoliciesHead)
        {
            dwError = pmd_gpmgmt_load_each_policy(
                pKey,
                pValue,
                &pPolicy);
            BAIL_ON_PMD_ERROR(dwError);

            pPoliciesHead = pPolicy;
        }
        else
        {
            dwError = pmd_gpmgmt_load_each_policy(
                pKey,
                pValue,
                &(pPolicy->pNext));
            BAIL_ON_PMD_ERROR(dwError);

            pPolicy = pPolicy->pNext;
        }
    }

    *ppPolicies = pPoliciesHead;

cleanup :
    PMD_SAFE_FREE_MEMORY(pszPolicyJsonPath);
    if(root)
    {
        json_decref(root);
    }
    return dwError;

error :
    fprintf(stderr, "Error in loading policies\"\n");
    if (ppPolicies)
    {
         *ppPolicies = NULL;
    }
    gpmgmt_free_policies(pPoliciesHead);
    goto cleanup;
}

uint32_t
pmd_gpmgmt_print_polices(
    PPMD_POLICY_DATA pPolicies)
{
    uint32_t dwError = 0;
    uint32_t i;
    struct tm *ptmInfo;
    char szTimeStr[20];

    fprintf(stdout,"Priniting Policies \n");
    fprintf(stdout, "==================================================================\n");

    if(!pPolicies)
        fprintf(stdout,"No policies to print \n");

    while (pPolicies)
    {
        fprintf(stdout, "Name                   :%s\n", pPolicies->pszPolicyName);
        fprintf(stdout, "kind                   :%d\n", pPolicies->nKind);
        fprintf(stdout, "Order                  :%d\n", pPolicies->nOrder);
        fprintf(stdout, "Enable                 :%d\n", pPolicies->nEnabled);
        ptmInfo = localtime(&pPolicies->tmStartTime);
        strftime(szTimeStr,sizeof(szTimeStr),"%b %d %H:: %M",ptmInfo);
        fprintf(stdout, "Starttype              :%s\n", szTimeStr);
        fprintf(stdout, "Interval               :%ld\n", pPolicies->lInterval);
        ptmInfo = localtime(&pPolicies->tmLastEnforced);
        strftime(szTimeStr,sizeof(szTimeStr),"%b %d %H:: %M",ptmInfo);
        fprintf(stdout, "Last Implemented       :%s\n", szTimeStr);
        fprintf(stdout, "Policy Json            :%s\n", json_dumps(pPolicies->pszPolicyData,JSON_INDENT(2)));
        fprintf(stdout, "==================================================================\n");

        pPolicies = pPolicies->pNext;
    }

    return dwError;
}

uint32_t
pmd_gpmgmt_load_each_policy(
    const char *pszPolicyName,
    json_t *pPolicyData,
    PPMD_POLICY_DATA *ppPolicy
    )
{
    uint32_t dwError =0;
    PPMD_POLICY_DATA pPolicy =NULL;
    json_error_t error;
    const char *pKey = NULL;
    json_t *pValue = NULL;
    const char *pszTempStr = NULL;
    int  nTempInt =0;
    json_t *ptempJson = NULL;
    bool isJson = false;

    uint32_t *pnKind = NULL;
    uint32_t *pnType = NULL;
    time_t  *ptmStart = NULL;
    long lInterval = 0;

    dwError = PMDAllocateMemory(sizeof(PMD_POLICY_DATA),(void **)&pPolicy);
    BAIL_ON_PMD_ERROR(dwError);

    pPolicy->pszPolicyName = NULL;
    pPolicy->pszPolicyData = NULL;
    pPolicy->pNext = NULL;

    dwError =PMDAllocateString(pszPolicyName,&pPolicy->pszPolicyName);
    BAIL_ON_PMD_ERROR(dwError);

    json_object_foreach(pPolicyData, pKey, pValue)
    {
        if (!strcmp(pKey, "kind"))
        {
            isJson = json_is_string(pValue);
            if(!isJson)
            {
                dwError= ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
                BAIL_ON_PMD_ERROR(dwError);
            }
            pszTempStr = json_string_value(pValue);

            dwError = gpmgmt_get_policy_kind_enum(pszTempStr, &pnKind);
            BAIL_ON_PMD_ERROR(dwError);

            pPolicy->nKind = *pnKind;
        }
        else if (!strcmp(pKey, "type"))
        {
            isJson = json_is_string(pValue);
            if(!isJson)
            {
                dwError= ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
                BAIL_ON_PMD_ERROR(dwError);
            }
            pszTempStr = json_string_value(pValue);

            dwError = gpmgmt_get_policy_type_enum(pszTempStr,&pnType);
            BAIL_ON_PMD_ERROR(dwError);

            pPolicy->nType = *pnType;
        }
        else if(!strcmp(pKey,"order"))
        {
            nTempInt = json_integer_value(pValue);
            if(nTempInt == 0)
            {
                dwError= ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
                BAIL_ON_PMD_ERROR(dwError);
            }

            pPolicy->nOrder = nTempInt;
        }
        else if(!strcmp(pKey,"enabled"))
        {
            isJson = json_is_boolean(pValue);
            if(!isJson)
            {
                dwError= ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
                BAIL_ON_PMD_ERROR(dwError);
            }

            pPolicy->nEnabled = json_is_true(pValue)? true : false;
        }
        else if(!strcmp(pKey,"start_time"))
        {
            isJson = json_is_string(pValue);
            if(!isJson)
            {
                dwError= ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
                BAIL_ON_PMD_ERROR(dwError);
            }
            pszTempStr = json_string_value(pValue);

            dwError =gpmgmt_get_policy_time(pszTempStr,&ptmStart);
            BAIL_ON_PMD_ERROR(dwError);

            pPolicy->tmStartTime = *ptmStart;

        }
        else if(!strcmp(pKey,"interval"))
        {
            isJson = json_is_string(pValue);
            if(!isJson)
            {
                dwError= ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
                BAIL_ON_PMD_ERROR(dwError);
            }
            pszTempStr = json_string_value(pValue);

            dwError = gpmgmt_get_policy_interval(pszTempStr,&lInterval);
            BAIL_ON_PMD_ERROR(dwError);

            pPolicy->lInterval = lInterval;

        }
        else if(!strcmp(pKey,"policy_info"))
        {
            ptempJson = json_deep_copy(pValue);
            if(!ptempJson)
            {
                BAIL_ON_PMD_ERROR(dwError);
            }

            pPolicy->pszPolicyData = ptempJson;
        }
        else
        {
            fprintf(stderr, "Key cannot be recongised in the policy json: \" %s \"\n", pKey);
            dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_KEY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        //Init the lastImplemented to zero.
        pPolicy->tmLastEnforced =0;
    }

    *ppPolicy = pPolicy;

cleanup:
    PMD_SAFE_FREE_MEMORY(pnKind);
    PMD_SAFE_FREE_MEMORY(pnType);
    PMD_SAFE_FREE_MEMORY(ptmStart);
    return dwError;

error:
    fprintf(stderr, "Error in parsing each policy\"\n");
    gpmgmt_free_policies(pPolicy);
    if(ppPolicy)
    {
        *ppPolicy = NULL;
    }
    goto cleanup;
}

//Creating a sample json
uint32_t
pmd_gpmgmt_create_policy_json(
        )
{
    int nError =0;
    uint32_t dwError =0;

    json_t *pRoot = json_object();
    json_t *pSubObj = json_object();
    json_t *pSubSubObj = json_object();

    nError = json_object_set_new( pRoot, "updatepolicy", pSubObj );
    nError = json_object_set_new( pSubObj, "kind", json_string("domain") );
    nError = json_object_set_new( pSubObj, "type", json_string("update") );
    nError = json_object_set_new( pSubObj, "order", json_integer(1) );
    nError = json_object_set_new( pSubObj, "enabled", json_true() );
    nError = json_object_set_new( pSubObj, "starttime", json_string("2015-05-30 18:13:04") );
    nError = json_object_set_new( pSubObj, "interval", json_string("2015-05-30 18:13:04") );
    nError = json_object_set_new( pSubObj, "policy_data",pSubSubObj);

    nError = json_object_set_new( pSubSubObj, "type", json_string("updatepackage") );
    nError = json_object_set_new( pSubSubObj, "package", json_string("diffutils") );

    if(nError == -1)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_PARSE_ERROR;
        BAIL_ON_PMD_ERROR(dwError);
    }

    json_decref(pRoot);

cleanup:
    return dwError;

error:
    fprintf(stderr, "Error in creating the policy json\"\n");
    goto cleanup;
}

void
gpmgmt_free_policies(
    PPMD_POLICY_DATA pPolicies
    )
{
    PPMD_POLICY_DATA pPoliciesPrev = NULL;

    while(pPolicies)
    {
        PMD_SAFE_FREE_MEMORY(pPolicies->pszPolicyName);
        if(pPolicies->pszPolicyData)
        {
            json_decref(pPolicies->pszPolicyData);
        }
        pPoliciesPrev = pPolicies;
        pPolicies = pPolicies->pNext;
        PMD_SAFE_FREE_MEMORY(pPoliciesPrev);
    }
}