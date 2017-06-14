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
rolemgmt_free_role(
    PPMD_ROLEMGMT_ROLE pRole
    );

void
rolemgmt_free_children(
    PPMD_ROLEMGMT_ROLE pRole
    )
{
    int i = 0;
    for(i = 0; i < pRole->nChildCount; ++i)
    {
        rolemgmt_free_role(pRole->ppChildren[i]);
    }
    PMD_SAFE_FREE_MEMORY(pRole->ppChildren);
}

void
rolemgmt_free_role(
    PPMD_ROLEMGMT_ROLE pRole
    )
{
    int i = 0;
    if(!pRole)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pRole->pszName);
    PMD_SAFE_FREE_MEMORY(pRole->pszParent);
    PMD_SAFE_FREE_MEMORY(pRole->pszDisplayName);
    PMD_SAFE_FREE_MEMORY(pRole->pszDescription);
    PMD_SAFE_FREE_MEMORY(pRole->pszPlugin);
    rolemgmt_free_children(pRole);
    PMDFreeMemory(pRole);
}

void
rolemgmt_free_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    )
{
    if(!pRoles)
    {
        return;
    }
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    while(pRoles)
    {
        pRole = pRoles->pNext;
        rolemgmt_free_role(pRoles);
        pRoles = pRole;
    }
}
