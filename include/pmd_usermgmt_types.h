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

typedef struct _PMD_USER_
{
    char *pszName;
    uint32_t nUID;
    uint32_t nGID;
    char *pszRealName;
    char *pszHomeDir;
    char *pszShell;

    struct _PMD_USER_ *pNext;
}PMD_USER, *PPMD_USER;

typedef struct _PMD_GROUP_
{
    char *pszName;
    uint32_t nGID;
    char **pszMembers;

    struct _PMD_GROUP_ *pNext;
}PMD_GROUP, *PPMD_GROUP;

#ifdef __cplusplus
}
#endif
