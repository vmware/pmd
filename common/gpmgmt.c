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
gpmgmt_get_policy_kind_enum(
    const char *pPolicyKind,
    PMD_POLICY_KIND *penumKindRet
    )
{
    uint32_t i = 0;
    uint32_t dwError = 0;
    bool bValidString = false;
    PMD_POLICY_KIND_MAP policyKindMap[] = {
        {POLICY_KIND_LOCAL, "local"},
        {POLICY_KIND_SITE, "site"},
        {POLICY_KIND_DOMAIN, "domain"},
        {POLICY_KIND_OU, "ou"}};
    PMD_POLICY_KIND *penumKind = NULL;

    dwError = PMDAllocateMemory(sizeof(PMD_POLICY_KIND), (void **)&penumKind);
    BAIL_ON_PMD_ERROR(dwError);

    for (i = 0; i < sizeof(policyKindMap) / sizeof(policyKindMap[0]); i++)
    {
        if (!strcmp(pPolicyKind, policyKindMap[i].str))
        {
            memcpy(penumKind, &policyKindMap[i].kind, sizeof(PMD_POLICY_KIND));
            bValidString = true;
        }
    }

    if(!bValidString)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }
    *penumKindRet = *penumKind;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(penumKind);
    PMD_SAFE_FREE_MEMORY(penumKindRet);
    goto cleanup;
}

uint32_t
gpmgmt_get_policy_type_enum(
    const char *pPolicyType,
    PMD_POLICY_TYPE *penumTypeRet
    )
{
    uint32_t i = 0;
    uint32_t dwError = 0;
    bool bValidString = false;
    PMD_POLICY_TYPE_MAP policyTypeMap[] = {
        {POLICY_TYPE_UNKNOWN, "other"},
        {POLICY_TYPE_UPDATE, "update"},
    };
    PMD_POLICY_TYPE *penumType = NULL;

    dwError = PMDAllocateMemory(sizeof(PMD_POLICY_TYPE), (void **)&penumType);
    BAIL_ON_PMD_ERROR(dwError);

    for (i = 0; i < sizeof(policyTypeMap) / sizeof(policyTypeMap[0]); i++)
    {
        if (!strcmp(pPolicyType, policyTypeMap[i].str))
        {
            memcpy(penumType, &policyTypeMap[i].type, sizeof(PMD_POLICY_TYPE));
            bValidString = true;
        }
    }

    if(!bValidString)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *penumTypeRet = *penumType;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(penumType);
    PMD_SAFE_FREE_MEMORY(penumTypeRet);
    goto cleanup;
}

uint32_t
gpmgmt_get_policy_enabled_enum(
    const char *pPolicyEnable,
    PMD_POLICY_ENABLE *penumEnableRet
    )
{
    uint32_t i = 0;
    uint32_t dwError = 0;
    bool bValidString = false;
    PMD_POLICY_ENABLE_MAP policyEnableMap[] = {
        {POLICY_ENABLED, "true"},
        {POLICY_DISABLED, "false"},
    };
    PMD_POLICY_ENABLE *penumEnable = NULL;

    dwError = PMDAllocateMemory(sizeof(PMD_POLICY_ENABLE_MAP), (void **)&penumEnable);
    BAIL_ON_PMD_ERROR(dwError);

    for (i = 0; i < sizeof(policyEnableMap) / sizeof(policyEnableMap[0]); i++)
    {
        if (!strcmp(pPolicyEnable, policyEnableMap[i].str))
        {
            memcpy(penumEnable, &policyEnableMap[i].enable, sizeof(PMD_POLICY_ENABLE_MAP));
            bValidString = true;
        }
    }

    if(!bValidString)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_VALUE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *penumEnableRet = *penumEnable;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(penumEnableRet);
    PMD_SAFE_FREE_MEMORY(penumEnable);
    goto cleanup;
}

uint32_t
gpmgmt_get_policy_time(
    const char *pPolicyTime,
    time_t *ptmTimeRet
    )
{
    uint32_t i = 0;
    uint32_t dwError = 0;
    time_t *ptmTime = NULL;
    uint32_t years = 0, month = 0, days = 0;
    uint32_t hours = 0, minutes = 0, seconds = 0;
    struct tm tmMaker;

    dwError = PMDAllocateMemory(sizeof(time_t), (void **)&ptmTime);
    BAIL_ON_PMD_ERROR(dwError);

    if (sscanf(pPolicyTime, "%u-%u-%u %u:%u:%u", &years, &month, &days, &hours, &minutes, &seconds) != 6)
        dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_TIME_FMT;

    tmMaker.tm_sec = seconds;
    tmMaker.tm_min = minutes;
    tmMaker.tm_hour = hours;
    tmMaker.tm_mday = days;
    tmMaker.tm_mon = month - 1;
    tmMaker.tm_year = years - 1900;
    tmMaker.tm_isdst = -1; // daylight savings is unknown

    *ptmTime = mktime(&tmMaker);
    *ptmTimeRet = *ptmTime;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(ptmTimeRet);
    PMD_SAFE_FREE_MEMORY(ptmTime);
    goto cleanup;
}

uint32_t
gpmgmt_get_policy_interval(
    const char *pPolicyTime,
    time_t *ptmTimeRet
    )
{
    uint32_t i = 0;
    uint32_t dwError = 0;
    time_t *ptmTime = NULL;
    uint32_t years = 0, month = 0, days = 0;
    uint32_t hours = 0, minutes = 0, seconds = 0;
    struct tm tmMaker;

    dwError = PMDAllocateMemory(sizeof(time_t), (void **)&ptmTime);
    BAIL_ON_PMD_ERROR(dwError);

    if (sscanf(pPolicyTime, "%u-%u-%u %u:%u:%u", &years, &month, &days, &hours, &minutes, &seconds) != 6)
        dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_TIME_FMT;

    tmMaker.tm_sec = seconds;
    tmMaker.tm_min = minutes;
    tmMaker.tm_hour = hours;
    tmMaker.tm_mday = days;
    tmMaker.tm_mon = month;
    tmMaker.tm_year = years;
    tmMaker.tm_isdst = -1; // daylight savings is unknown

    *ptmTime = mktime(&tmMaker);
    *ptmTimeRet = *ptmTime;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(ptmTimeRet);
    PMD_SAFE_FREE_MEMORY(ptmTime);
    goto cleanup;
}

