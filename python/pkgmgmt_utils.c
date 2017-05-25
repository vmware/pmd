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
pkg_get_cmd_string(
    TDNF_ALTERTYPE nAlterType,
    char ** ppszAlterCmd
    )
{
    uint32_t dwError = 0;
    char *pszAlterCmd = NULL;

    if(nAlterType == ALTER_INSTALL)
    {
        dwError = PMDAllocateString("install", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_UPGRADE)
    {
        dwError = PMDAllocateString("update", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_ERASE)
    {
        dwError = PMDAllocateString("erase", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_DOWNGRADE)
    {
        dwError = PMDAllocateString("downgrade", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_REINSTALL)
    {
        dwError = PMDAllocateString("reinstall", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(nAlterType == ALTER_DISTRO_SYNC)
    {
        dwError = PMDAllocateString("distro-sync", &pszAlterCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        nAlterType = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszAlterCmd = pszAlterCmd;
cleanup:
    return dwError;

error:
    if(ppszAlterCmd)
    {
        *ppszAlterCmd = NULL;
    }
    goto cleanup;
}

uint32_t
pkg_translate_alter_cmd(
    int nPkgCount,
    TDNF_ALTERTYPE alterType,
    TDNF_ALTERTYPE *palterTypeToUse)
{
    uint32_t dwError = 0;
    TDNF_ALTERTYPE alterTypeToUse = alterType;

    if(!palterTypeToUse)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    switch(alterType)
    {
        case ALTER_REINSTALL:
        case ALTER_INSTALL:
        case ALTER_ERASE:
            if(nPkgCount <= 0)
            {
                dwError = ERROR_PMD_MISSING_PKG_ARGS;
                BAIL_ON_PMD_ERROR(dwError);
            }
        break;
        case ALTER_UPGRADE:
            if(nPkgCount <= 0)
            {
                alterTypeToUse = ALTER_UPGRADEALL;
            }
        break;
        case ALTER_DOWNGRADE:
            if(nPkgCount <= 0)
            {
                alterTypeToUse = ALTER_DOWNGRADEALL;
            }
        break;
        case ALTER_DISTRO_SYNC:
            alterTypeToUse = ALTER_DISTRO_SYNC;
        break;
        default:
            dwError = ERROR_PMD_ALTER_MODE_INVALID;
            BAIL_ON_PMD_ERROR(dwError);
    }

    *palterTypeToUse = alterTypeToUse;

cleanup:
    return dwError;

error:
    if(palterTypeToUse)
    {
        *palterTypeToUse = alterType;
    }
    goto cleanup;
}
