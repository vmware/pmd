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

void
usermgmt_free_user(
    PPMD_USER pUser
    )
{
    if(!pUser)
    {
        return;
    }
    while(pUser)
    {
        PPMD_USER pTemp = pUser->pNext;
        PMD_SAFE_FREE_MEMORY(pUser->pszName);
        PMD_SAFE_FREE_MEMORY(pUser->pszRealName);
        PMD_SAFE_FREE_MEMORY(pUser->pszHomeDir);
        PMD_SAFE_FREE_MEMORY(pUser->pszShell);
        PMDFreeMemory(pUser);
        pUser = pTemp;
    }
}

void
usermgmt_free_group(
    PPMD_GROUP pGroup
    )
{
    if(!pGroup)
    {
        return;
    }
    while(pGroup)
    {
        PPMD_GROUP pTemp = pGroup->pNext;
        PMD_SAFE_FREE_MEMORY(pGroup->pszName);
        PMDFreeMemory(pGroup);
        pGroup = pTemp;
    }
}
