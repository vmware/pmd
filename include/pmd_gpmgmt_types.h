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

 #pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <time.h>
#include <jansson.h>
#include <stdbool.h>

typedef enum
{
    POLICY_KIND_LOCAL,
    POLICY_KIND_SITE,
    POLICY_KIND_DOMAIN,
    POLICY_KIND_OU,
}PMD_POLICY_KIND;

typedef enum
{
    POLICY_TYPE_UNKNOWN,
    POLICY_TYPE_UPDATE
}PMD_POLICY_TYPE;

typedef enum
{
    POLICY_ENABLED,
    POLICY_DISABLED
}PMD_POLICY_ENABLE;


typedef const struct _PMD_POLICY_KIND_MAP_
{
    PMD_POLICY_KIND  kind;
    const char *str;
} PMD_POLICY_KIND_MAP;


typedef const struct _PMD_POLICY_TYPE_MAP_
{
    PMD_POLICY_TYPE  type;
    const char *str;
}PMD_POLICY_TYPE_MAP; 

typedef const struct _PMD_POLICY_ENABLE_MAP_
{
    PMD_POLICY_ENABLE  enable;
    const char *str;
}PMD_POLICY_ENABLE_MAP; 


typedef struct _PMD_POLICY_DATA_
{
    //Generic details loaded from file
    char *pszPolicyName;
    PMD_POLICY_KIND nKind;
    PMD_POLICY_TYPE nType;
    int nOrder;
    bool nEnabled;
    time_t tmStartTime;
    time_t tmInterval;
    // Written by the thread
    time_t tmLastImplemented;
    //Policy speciifc details 
    json_t *pszPolicyData;
    struct _PMD_POLICY_DATA_ *pNext;
}PMD_POLICY_DATA, *PPMD_POLICY_DATA;

#ifdef __cplusplus
}
#endif