/*
 * Copyright 2017 VMware, Inc. All rights reserved.
 * This software is released under the BSD 2-Clause license.
 * The full license information can be found in the LICENSE
 * in the root directory of this project.
 * SPDX-License-Identifier: BSD-2
*/

#include "includes.h"

uint32_t
rolemgmt_load_roles(
    const char *pszRolesDir,
    const char *pszPluginsDir,
    PPMD_ROLEMGMT_ROLE *ppAllRoles
    )
{
    uint32_t dwError = 0;
    PPMD_CONFIG_ITEM pItems = NULL;
    PPMD_CONFIG_ITEM pItem = NULL;
    PPMD_ROLEMGMT_ROLE *ppRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    int nRoleCount = 0;

    dwError = rolemgmt_read_roles(pszRolesDir, &pItems);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rolemgmt_copy_roles(pItems, &ppRoles, &nRoleCount);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rolemgmt_move_role_parents(pItems, ppRoles, nRoleCount, &pRoles);
    BAIL_ON_PMD_ERROR(dwError);

    for(pRole = pRoles; pRole; pRole = pRole->pNext)
    {
        dwError = rolemgmt_move_role_children(
                      pRole,
                      ppRoles,
                      nRoleCount);
        BAIL_ON_PMD_ERROR(dwError);
    }

    print_roles(pRoles);

    *ppAllRoles = pRoles;
cleanup:
    PMD_SAFE_FREE_MEMORY(ppRoles);
    rolemgmt_free_items(pItems);
    return dwError;

error:
    if(ppAllRoles)
    {
        *ppAllRoles = NULL;
    }
    rolemgmt_free_roles(pRoles);
    goto cleanup;
}

uint32_t
rolemgmt_move_role_parents(
    PPMD_CONFIG_ITEM pItems,
    PPMD_ROLEMGMT_ROLE *ppRoleArray,
    int nRoleCount,
    PPMD_ROLEMGMT_ROLE *ppRoles
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_CONFIG_ITEM pItem = NULL;

    if(!pItems || !ppRoleArray || !ppRoles)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pItem = pItems; pItem; pItem = pItem->pNext)
    {
        PPMD_ROLEMGMT_ROLE pTemp = NULL;
        int i = 0;

        if(!IsNullOrEmptyString(pItem->pszParent)) continue;

        for(i = 0; i < nRoleCount; ++i)
        {
            if(!ppRoleArray[i]) continue;

            if(!strcmp(ppRoleArray[i]->pszName, pItem->pszName))
            {
                pTemp = ppRoleArray[i];
                break;
            }
        }
        if(!pTemp)
        {
            fprintf(stderr,
                    "Could not move role parent for %s\n",
                    pItem->pszName);
            dwError = ERROR_PMD_ROLE_CONFIG_NO_PARENT;
            BAIL_ON_PMD_ERROR(dwError);
        }
        pTemp->pNext = pRoles;
        pRoles = pTemp;
        ppRoleArray[i] = NULL;
    }

    *ppRoles = pRoles;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_get_children_of(
    const char *pszParent,
    PPMD_ROLEMGMT_ROLE *ppRoles,
    int nRoleCount,
    PPMD_ROLEMGMT_ROLE **pppChildren,
    int *pnChildCount
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_ROLE *ppChildren = NULL;
    int nChildCount = 0;
    int i = 0;

    if(IsNullOrEmptyString(pszParent) ||
       !ppRoles||
       !pppChildren ||
       !pnChildCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < nRoleCount; ++i)
    {
        if(!ppRoles[i]) continue;
        if(!strcmp(pszParent, ppRoles[i]->pszParent))
        {
            ++nChildCount;
        }
    }

    if(nChildCount > 0)
    {
        int j = 0;
        dwError = PMDAllocateMemory(sizeof(PPMD_ROLEMGMT_ROLE) * nChildCount,
                                    (void **)&ppChildren);
        BAIL_ON_PMD_ERROR(dwError);

        for(i = 0; i < nRoleCount; ++i)
        {
            if(!ppRoles[i]) continue;
            if(!strcmp(pszParent, ppRoles[i]->pszParent))
            {
                ppChildren[j++] =  ppRoles[i];
                ppRoles[i] = NULL;
            }
        }
    }

    *pppChildren = ppChildren;
    *pnChildCount = nChildCount;

cleanup:
    return dwError;

error:
    if(pppChildren)
    {
        *pppChildren = ppChildren;
    }
    if(pnChildCount)
    {
        *pnChildCount = 0;
    }
    goto cleanup;
}


uint32_t
rolemgmt_move_role_children(
    PPMD_ROLEMGMT_ROLE pRole,
    PPMD_ROLEMGMT_ROLE *ppRoleArray,
    int nRoleCount
    )
{
    uint32_t dwError = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE *ppChildren = NULL;
    int i = 0;

    if(!pRole || !ppRoleArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_get_children_of(
                  pRole->pszId,
                  ppRoleArray,
                  nRoleCount,
                  &pRole->ppChildren,
                  &pRole->nChildCount);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0; i < pRole->nChildCount; ++i)
    {
        dwError = rolemgmt_move_role_children(
                      pRole->ppChildren[i],
                      ppRoleArray,
                      nRoleCount);
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rolemgmt_copy_roles(
    PPMD_CONFIG_ITEM pItems,
    PPMD_ROLEMGMT_ROLE **pppRoles,
    int *pnRoleCount
    )
{
    uint32_t dwError = 0;
    PPMD_CONFIG_ITEM pItem = NULL;
    PPMD_ROLEMGMT_ROLE *ppRoles = NULL;
    int nRoleCount = 0;
    int i = 0;

    for(pItem = pItems; pItem; pItem = pItem->pNext) ++nRoleCount;

    dwError = PMDAllocateMemory(sizeof(PPMD_ROLEMGMT_ROLE) * nRoleCount,
                                (void **)&ppRoles);
    BAIL_ON_PMD_ERROR(dwError);

    for(pItem = pItems, i = 0; pItem; pItem = pItem->pNext, ++i)
    {
        PPMD_ROLEMGMT_ROLE pRole = NULL;

        dwError = PMDAllocateMemory(sizeof(PMD_ROLEMGMT_ROLE), (void **)&ppRoles[i]);
        BAIL_ON_PMD_ERROR(dwError);

        pRole = ppRoles[i];

        dwError = PMDAllocateString(pItem->pszId, &pRole->pszId);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pItem->pszName, &pRole->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDSafeAllocateString(pItem->pszParent, &pRole->pszParent);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDSafeAllocateString(pItem->pszDisplayName, &pRole->pszDisplayName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDSafeAllocateString(pItem->pszDescription, &pRole->pszDescription);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDSafeAllocateString(pItem->pszPlugin, &pRole->pszPlugin);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pppRoles = ppRoles;
    *pnRoleCount = nRoleCount;

cleanup:
    return dwError;

error:
    if(pppRoles)
    {
        *pppRoles = NULL;
    }
    if(pnRoleCount)
    {
        *pnRoleCount = 0;
    }
    for(i = 0; i < nRoleCount; ++i)
    {
        rolemgmt_free_roles(ppRoles[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppRoles);
    goto cleanup;
}

uint32_t
rolemgmt_read_roles(
    const char *pszRolesDir,
    PPMD_CONFIG_ITEM *ppItemsAll
    )
{
    DIR *pDir = NULL;
    struct dirent *pEnt = NULL;
    int nLen = 0;
    int nLenExt = 0;
    PPMD_CONFIG_ITEM pItemsAll = NULL;
    char *pszRoleFile = NULL;
    uint32_t dwError = 0;

    pDir = opendir(pszRolesDir);
    if(pDir == NULL)
    {
        dwError = ERROR_PMD_ROLES_DIR_OPEN;
        BAIL_ON_PMD_ERROR(dwError);
    }

    while ((pEnt = readdir (pDir)) != NULL )
    {
        PPMD_CONFIG_ITEM pItems = NULL;
        PPMD_CONFIG_ITEM pItemsTail = NULL;

        nLen = strlen(pEnt->d_name);
        if (nLen <= PMD_ROLE_EXT_LEN ||
            strcmp(pEnt->d_name + nLen - PMD_ROLE_EXT_LEN, PMD_ROLE_EXT))
        {
            continue;
        }

        dwError = PMDAllocateStringPrintf(
                      &pszRoleFile,
                      "%s/%s",
                      pszRolesDir,
                      pEnt->d_name);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = rolemgmt_read_role(pszRoleFile, &pItems);
        BAIL_ON_PMD_ERROR(dwError);

        PMD_SAFE_FREE_MEMORY(pszRoleFile);
        pszRoleFile = NULL;

        pItemsTail = pItems;
	if(pItems)
        {
            while(pItems->pNext) pItems = pItems->pNext;
	    pItems->pNext = pItemsAll;
            pItemsAll = pItemsTail;
            pItems = NULL;
	}
    }

    if(!pItemsAll)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppItemsAll = pItemsAll;
cleanup:
    if(pDir)
    {
        closedir(pDir);
    }
    PMD_SAFE_FREE_MEMORY(pszRoleFile);
    return dwError;

error:
    if(ppItemsAll)
    {
        *ppItemsAll = NULL;
    }
    rolemgmt_free_items(pItemsAll);
    goto cleanup;
}

uint32_t
rolemgmt_read_role(
    const char *pszRoleFile,
    PPMD_CONFIG_ITEM *ppItems
    )
{
    uint32_t dwError = 0;
    PCONF_DATA pData = NULL;
    PCONF_SECTION pSection = NULL;
    PPMD_CONFIG_ITEM pItems = NULL;
    PPMD_CONFIG_ITEM pItem = NULL;

    if(IsNullOrEmptyString(pszRoleFile) || !ppItems)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = read_config_file(pszRoleFile,
                               MAX_CONFIG_LINE_LENGTH,
                               &pData);
    BAIL_ON_PMD_ERROR(dwError);

    for(pSection = pData->pSections; pSection; pSection = pSection->pNext)
    {
        dwError = PMDAllocateMemory(sizeof(PMD_CONFIG_ITEM),
                                    (void **)&pItem);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pSection->pszName, &pItem->pszId);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = rolemgmt_load_item_data(pItem, pSection);
        BAIL_ON_PMD_ERROR(dwError);

        pItem->pNext = pItems;
        pItems = pItem;
        pItem = NULL;
    }

    *ppItems = pItems;

cleanup:
    free_config_data(pData);
    return dwError;

error:
    if(ppItems)
    {
        *ppItems = NULL;
    }
    rolemgmt_free_items(pItems);
    rolemgmt_free_item(pItem);
    goto cleanup;
}

uint32_t
rolemgmt_load_item_data(
    PPMD_CONFIG_ITEM pItem,
    PCONF_SECTION pSection
    )
{
    uint32_t dwError = 0;
    PKEYVALUE pKV = NULL;

    if(!pItem|| !pSection)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pKV = pSection->pKeyValues; pKV; pKV = pKV->pNext)
    {
        if(!strcmp(pKV->pszKey, ROLE_CONF_NAME))
        {
            dwError = PMDAllocateString(pKV->pszValue, &pItem->pszName);
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!strcmp(pKV->pszKey, ROLE_CONF_DISPLAY_NAME))
        {
            dwError = PMDAllocateString(pKV->pszValue, &pItem->pszDisplayName);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(pKV->pszKey, ROLE_CONF_DESCRIPTION))
        {
            dwError = PMDAllocateString(pKV->pszValue, &pItem->pszDescription);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(pKV->pszKey, ROLE_CONF_PARENT))
        {
            dwError = PMDAllocateString(pKV->pszValue, &pItem->pszParent);
            BAIL_ON_PMD_ERROR(dwError);
        }
        else if(!strcmp(pKV->pszKey, ROLE_CONF_PLUGIN))
        {
            dwError = PMDAllocateString(pKV->pszValue, &pItem->pszPlugin);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

void
print_role_children(
    PPMD_ROLEMGMT_ROLE pRole,
    int nLevel
    )
{
    int i = 0;
    if(!pRole) return;

    for(i = 0; i < pRole->nChildCount; ++i)
    {
        printf("%*c", nLevel * 2, ' ');
        printf("child = %s(%d)\n", pRole->ppChildren[i]->pszName, pRole->nChildCount);
        print_role_children(pRole->ppChildren[i], nLevel+1);
    }
}

void
print_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    )
{
    if(!pRoles) return;
    while(pRoles)
    {
        int i = 0;
        fprintf(stdout, "Name = %s (%d)\n", pRoles->pszName, pRoles->nChildCount);
        print_role_children(pRoles, 1);
        pRoles = pRoles->pNext;
    }
}

void
print_items(
    PPMD_CONFIG_ITEM pItems
    )
{
    if(!pItems) return;
    while(pItems)
    {
        fprintf(stdout, "Name = %s\n", pItems->pszName);
        pItems = pItems->pNext;
    }
}

void
rolemgmt_free_item(
    PPMD_CONFIG_ITEM pItem
    )
{
    if(!pItem)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pItem->pszName);
    PMD_SAFE_FREE_MEMORY(pItem->pszDisplayName);
    PMD_SAFE_FREE_MEMORY(pItem->pszDescription);
    PMD_SAFE_FREE_MEMORY(pItem->pszParent);
    PMD_SAFE_FREE_MEMORY(pItem->pszPlugin);
    PMDFreeMemory(pItem);
}

void
rolemgmt_free_items(
    PPMD_CONFIG_ITEM pItems
    )
{
    PPMD_CONFIG_ITEM pItem = NULL;
    if(!pItems)
    {
        return;
    }
    while(pItems)
    {
        pItem = pItems->pNext;
        rolemgmt_free_item(pItems);
        pItems = pItem;
    }
}
