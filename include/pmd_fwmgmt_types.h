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

typedef struct _PMD_FIREWALL_PARAM_
{
    int nFlag;
    char *pszName;
    char *pszValue;
    struct _PMD_FIREWALL_PARAM_ *pNext;
}PMD_FIREWALL_PARAM, *PPMD_FIREWALL_PARAM;

typedef struct _PMD_FIREWALL_RULE_
{
    char *pszRule;
    char *pszCmd;
    PPMD_FIREWALL_PARAM pParams;    
    struct _PMD_FIREWALL_RULE_ *pNext;
}PMD_FIREWALL_RULE, *PPMD_FIREWALL_RULE;

typedef struct _PMD_FIREWALL_CMD_
{
    char *pszRawCmd;
    struct _PMD_FIREWALL_CMD_ *pNext;
}PMD_FIREWALL_CMD, *PPMD_FIREWALL_CMD;

typedef struct _PMD_FIREWALL_TABLE_
{
    char *pszName;
    PPMD_FIREWALL_CMD pCmds;
    struct _PMD_FIREWALL_TABLE_ *pNext;
}PMD_FIREWALL_TABLE, *PPMD_FIREWALL_TABLE;

#ifdef __cplusplus
}
#endif
