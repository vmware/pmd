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

typedef struct _PMD_API_SECURITY_
{
    char *pszName;
    char *pszSDDL;
    struct _PMD_API_SECURITY_ *pNext;
}PMD_API_SECURITY, *PPMD_API_SECURITY;

typedef struct _PMD_MODULE_SECURITY_
{
    char *pszName;
    PPMD_API_SECURITY pApiSecurity;
    struct _PMD_MODULE_SECURITY_ *pNext;
}PMD_MODULE_SECURITY, *PPMD_MODULE_SECURITY;

typedef struct _PMD_SECURITY_CONTEXT_
{
    PPMD_MODULE_SECURITY pModuleSecurity;
}PMD_SECURITY_CONTEXT, *PPMD_SECURITY_CONTEXT;
