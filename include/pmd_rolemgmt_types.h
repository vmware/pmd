/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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

typedef struct _PMD_ROLEMGMT_ROLE_
{
    char *pszRole;
    char *pszId;
    char *pszName;
    char *pszDisplayName;
    char *pszDescription;
    char *pszParent;
    char *pszPlugin;
    int nChildCount;
    struct _PMD_ROLEMGMT_ROLE_ *pParent;
    struct _PMD_ROLEMGMT_ROLE_ **ppChildren;
    struct _PMD_ROLEMGMT_ROLE_ *pNext;
}PMD_ROLEMGMT_ROLE, *PPMD_ROLEMGMT_ROLE;

typedef struct _PMD_ROLEMGMT_TASK_LOG_
{
    time_t tStamp;
    char *pszLog;
}PMD_ROLEMGMT_TASK_LOG, *PPMD_ROLEMGMT_TASK_LOG;

#ifdef __cplusplus
}
#endif
