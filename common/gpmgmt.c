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
    PMD_POLICY_KIND **ppenumKind
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
    *ppenumKind = penumKind;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(penumKind);
    if(ppenumKind)
        ppenumKind = NULL;
    goto cleanup;
}

uint32_t
gpmgmt_get_policy_type_enum(
    const char *pPolicyType,
    PMD_POLICY_TYPE **ppenumType
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

    *ppenumType = penumType;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(penumType);
    if(ppenumType)
        ppenumType = NULL;
    goto cleanup;
}

uint32_t
gpmgmt_get_policy_time(
    const char *pPolicyTime,
    time_t **pptmTime
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
    *pptmTime = ptmTime;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(ptmTime);
    if(pptmTime)
        pptmTime = NULL;
    goto cleanup;
}



/* 
Interval can be 
1) Number string  "6"  => taken as 6 seconds
2) Time string    "6s" => taken as 6 seconds
3) Time string    "6h" => taken as 6 hours
4) Time string    "6d" => taken as 6 days
5) Empty String    ""  => Default implementation interval
*/
uint32_t
gpmgmt_get_policy_interval(
    const char *pPolicyInterval,
    int **ppdInterval)
{   
    uint32_t dwError = 0;
    char intStr[100];
    char timeStr[100];
    const char *pCh = NULL;
    int *pdInterval = NULL;
    int dTime = 0;
    int dLength = 0;
    int dTimeStrTotLen =0;
    int dTimeStrCharLen =0;

    dwError = PMDAllocateMemory(sizeof(int),(void**)&pdInterval);
    BAIL_ON_PMD_ERROR(dwError);
    
    dLength = strlen(pPolicyInterval);
    if (dLength > 100)
    {
        dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_TIME_FMT;
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if (dLength == 0)
    {
        *pdInterval = PMD_GPMGMT_DEFAULT_POLICY_INTERVAL;
    }
    else
    {
        pCh = pPolicyInterval;
        dTimeStrTotLen = strlen(pPolicyInterval);
        dLength = 0;
        while (*pCh >= '0' && *pCh <= '9' && (dLength <= dTimeStrTotLen))
        {
            dLength++;
            pCh++;
        }

        strncpy(intStr, pPolicyInterval, dLength);
        intStr[dLength] = '\0';
        dTime = atoi(intStr);
        if ((strlen(pPolicyInterval) - dLength) == 0)
        {
            *pdInterval = dTime;
        }
        else
        {   
            dTimeStrCharLen = strlen(pCh);
            strncpy(timeStr, pCh,dTimeStrCharLen);
            timeStr[dTimeStrCharLen] ='\0';
            if (!strcmp(timeStr, "d"))
            {
                *pdInterval = dTime * 24 * 3600;
            }
            else if (!strcmp(timeStr, "h"))
            {
                *pdInterval = dTime * 3600;
            }
            else if (!strcmp(timeStr, "s"))
            {
                *pdInterval = dTime * 3600;
            }
            else
            {
                dwError = ERROR_PMD_GPMGMT_JSON_UNKNOWN_TIME_FMT;
                BAIL_ON_PMD_ERROR(dwError);
            }
        }
    }

    *ppdInterval = pdInterval;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pdInterval);
    if(ppdInterval)
        ppdInterval = NULL;
    goto cleanup;
}