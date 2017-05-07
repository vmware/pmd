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

typedef struct _KEYVALUE_
{
    char *pszKey;
    char *pszValue;
    struct _KEYVALUE_ *pNext;
}KEYVALUE, *PKEYVALUE;

typedef struct _CONF_SECTION_
{
    char *pszName;
    PKEYVALUE pKeyValues;
    struct _CONF_SECTION_ *pNext;
}CONF_SECTION, *PCONF_SECTION;

typedef struct _CONF_DATA_
{
    char *pszConfFile;
    PCONF_SECTION pSections;
}CONF_DATA, *PCONF_DATA;

typedef uint32_t
(*PFN_CONF_SECTION_CB)(
    PCONF_DATA pData,
    const char *pszSection
    );

typedef uint32_t
(*PFN_CONF_KEYVALUE_CB)(
    PCONF_DATA pData,
    const char *pszKey,
    const char *pszValue
    );

typedef struct _PMD_ERROR_DESC
{
    int nCode;
    char* pszName;
    char* pszDesc;
}PMD_ERROR_DESC, *PPMD_ERROR_DESC;
