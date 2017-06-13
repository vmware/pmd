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
init_security_config(
    const char *pszApiSecurityConf,
    PPMD_SECURITY_CONTEXT *ppContext
    )
{
    uint32_t dwError = 0;
    PCONF_DATA pData = NULL;
    PPMD_SECURITY_CONTEXT pContext = NULL;

    if(IsNullOrEmptyString(pszApiSecurityConf) || !ppContext)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_SECURITY_CONTEXT),
                                (void **)&pContext);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = read_config_file(pszApiSecurityConf,
                               MAX_API_SECURITY_LINE_LENGTH,
                               &pData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = init_module_security(pData, &pContext->pModuleSecurity);
    BAIL_ON_PMD_ERROR(dwError);

    *ppContext = pContext;

cleanup:
    free_config_data(pData);
    return dwError;

error:
    if(ppContext)
    {
        *ppContext = NULL;
    }
    free_security_context(pContext);
    goto cleanup;
}

uint32_t
save_security_config(
    const char *pszApiSecurityConf,
    PPMD_SECURITY_CONTEXT *ppContext
    )
{
    uint32_t dwError = 0;
    if(IsNullOrEmptyString(pszApiSecurityConf))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
init_module_security(
    PCONF_DATA pData,
    PPMD_MODULE_SECURITY *ppModuleSecurity
    )
{
    uint32_t dwError = 0;
    PPMD_MODULE_SECURITY pModuleSecurity = NULL;
    PPMD_MODULE_SECURITY pModuleTemp = NULL;
    PCONF_SECTION pSection = NULL;

    if(!pData || !ppModuleSecurity)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pSection = pData->pSections; pSection; pSection = pSection->pNext)
    {
        PKEYVALUE pKeyValue = NULL;
        dwError = PMDAllocateMemory(sizeof(PMD_MODULE_SECURITY),
                                    (void **)&pModuleTemp);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(pSection->pszName,
                                    &pModuleTemp->pszName);
        BAIL_ON_PMD_ERROR(dwError);

        for(pKeyValue = pSection->pKeyValues;
            pKeyValue;
            pKeyValue = pKeyValue->pNext) 
        {
            PPMD_API_SECURITY pApiSecurity = NULL;
            dwError = PMDAllocateMemory(sizeof(PMD_API_SECURITY),
                                        (void **)&pModuleTemp->pApiSecurity);
            BAIL_ON_PMD_ERROR(dwError);

            pApiSecurity = pModuleTemp->pApiSecurity;

            dwError = PMDAllocateString(pKeyValue->pszKey,
                                        &pApiSecurity->pszName);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = PMDAllocateString(pKeyValue->pszValue,
                                        &pApiSecurity->pszSDDL);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pModuleTemp->pNext = pModuleSecurity;
        pModuleSecurity = pModuleTemp;
        pModuleTemp = NULL;
    }

    *ppModuleSecurity = pModuleSecurity;

cleanup:
    return dwError;

error:
    if(ppModuleSecurity)
    {
        *ppModuleSecurity = NULL;
    }
    free_module_security(pModuleTemp);
    free_module_security(pModuleSecurity);
    goto cleanup;
}


uint32_t
init_security_context(
    PPMD_SECURITY_CONTEXT pContext
    )
{
    uint32_t dwError = 0;
    PLW_MAP_SECURITY_CONTEXT pSecContext = NULL;

    if(!pContext)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pContext->pSecContext)
    {
        dwError = EALREADY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = LwMapSecurityInitialize();
    BAIL_ON_PMD_ERROR(dwError);

    dwError = LwMapSecurityCreateContext(&pSecContext);
    BAIL_ON_PMD_ERROR(dwError);


    pContext->pSecContext = pSecContext;

cleanup:
    return dwError;

error:
    if(dwError == EALREADY)
    {
        dwError = 0;
    }
    if(pSecContext)
    {
        LwMapSecurityFreeContext(&pSecContext);
    }
    goto cleanup;
}

uint32_t
absolute_from_relative_sd(
    PSECURITY_DESCRIPTOR_RELATIVE pRelative,
    PSECURITY_DESCRIPTOR_ABSOLUTE *ppAbsolute
    )
{
    uint32_t dwError = 0;
    PSECURITY_DESCRIPTOR_ABSOLUTE pAbsolute = NULL;
    PSID pOwnerSid = NULL;
    PSID pGroupSid = NULL;
    PACL pDacl = NULL;
    PACL pSacl = NULL;
    uint32_t nAbsSize = 0;
    uint32_t nOwnerSize = 0;
    uint32_t nGroupSize = 0;
    uint32_t nDaclSize = 0;
    uint32_t nSaclSize = 0;

    dwError = RtlSelfRelativeToAbsoluteSD(
                 pRelative,
                 pAbsolute,
                 &nAbsSize,
                 pDacl,
                 &nDaclSize,
                 pSacl,
                 &nSaclSize,
                 pOwnerSid,
                 &nOwnerSize,
                 pGroupSid,
                 &nGroupSize);
    if (dwError != STATUS_BUFFER_TOO_SMALL)
    {
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = PMDAllocateMemory(
                  SECURITY_DESCRIPTOR_ABSOLUTE_MIN_SIZE,
                  (void **)&pAbsolute);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = RtlCreateSecurityDescriptorAbsolute(
                  pAbsolute,
                  SECURITY_DESCRIPTOR_REVISION);
    BAIL_ON_PMD_ERROR(dwError);

    if (nDaclSize)
    {
        dwError = PMDAllocateMemory(nDaclSize, (void **)&pDacl);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (nSaclSize)
    {
        dwError = PMDAllocateMemory(nSaclSize, (void **)&pSacl);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (nOwnerSize)
    {
        dwError = PMDAllocateMemory(nOwnerSize, (void **)&pOwnerSid);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (nGroupSize)
    {
        dwError = PMDAllocateMemory(nGroupSize, (void **)&pGroupSid);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = RtlSelfRelativeToAbsoluteSD(
                 pRelative,
                 pAbsolute,
                 &nAbsSize,
                 pDacl,
                 &nDaclSize,
                 pSacl,
                 &nSaclSize,
                 pOwnerSid,
                 &nOwnerSize,
                 pGroupSid,
                 &nGroupSize);
    BAIL_ON_PMD_ERROR(dwError);

    *ppAbsolute = pAbsolute;

cleanup:
    return dwError;

error:
    PMD_SAFE_FREE_MEMORY(pOwnerSid);
    PMD_SAFE_FREE_MEMORY(pGroupSid);
    PMD_SAFE_FREE_MEMORY(pDacl);
    PMD_SAFE_FREE_MEMORY(pSacl);
    PMD_SAFE_FREE_MEMORY(pAbsolute);

    goto cleanup;
}

uint32_t
sddl_to_sec_abs(
    const char *pszSDDL,
    PSECURITY_DESCRIPTOR_ABSOLUTE *ppSecAbs
    )
{
    uint32_t dwError = 0;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    uint32_t dwSize = 0;
    PSECURITY_DESCRIPTOR_ABSOLUTE pSecAbs = NULL;
    PSECURITY_DESCRIPTOR_RELATIVE pSecRel = NULL;

    if(IsNullOrEmptyString(pszSDDL) || !ppSecAbs)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        BAIL_ON_NT_STATUS(ntStatus);
    }

    ntStatus = RtlAllocateSecurityDescriptorFromSddlCString(
                        &pSecRel,
                        &dwSize,
                        pszSDDL,
                        SDDL_REVISION_1);
    if (ntStatus == STATUS_BUFFER_TOO_SMALL)
    {
        ntStatus = STATUS_SUCCESS;
    }
    BAIL_ON_NT_STATUS(ntStatus);

    dwError = PMDAllocateMemory(dwSize, (void **)&pSecAbs);
    BAIL_ON_PMD_ERROR(dwError);

    ntStatus = RtlAllocateSecurityDescriptorFromSddlCString(
                        &pSecRel,
                        &dwSize,
                        pszSDDL,
                        SDDL_REVISION_1);
    BAIL_ON_NT_STATUS(ntStatus);

    ntStatus = absolute_from_relative_sd(pSecRel, &pSecAbs);
    BAIL_ON_NT_STATUS(ntStatus);

    *ppSecAbs = pSecAbs;

cleanup:
    return dwError;

error:
    if(ppSecAbs)
    {
        *ppSecAbs = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pSecAbs);
    goto cleanup;
}

uint32_t
init_security_abs(
    PPMD_SECURITY_CONTEXT pContext,
    PPMD_API_SECURITY pApiSecurity
    )
{
    uint32_t dwError = 0;

    if(!pContext || !pApiSecurity)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pContext->pSecContext)
    {
        dwError = init_security_context(pContext);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pApiSecurity->pSecAbs)
    {
        dwError = sddl_to_sec_abs(pApiSecurity->pszSDDL,
                                  &pApiSecurity->pSecAbs);
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
find_module_api(
    PPMD_SECURITY_CONTEXT pContext,
    const char *pszModule,
    const char *pszApiName,
    PPMD_API_SECURITY *ppApiSecurity
    )
{
    uint32_t dwError = 0;
    PPMD_MODULE_SECURITY pModule = NULL;
    PPMD_API_SECURITY pApiSecurity = NULL;

    if(!pContext ||
       !pContext->pModuleSecurity ||
       IsNullOrEmptyString(pszModule) ||
       IsNullOrEmptyString(pszApiName) ||
       !ppApiSecurity)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pModule = pContext->pModuleSecurity;
    for(; pModule; pModule = pModule->pNext)
    {
        if(!strcmp(pModule->pszName, pszModule))
        {
            pApiSecurity = pModule->pApiSecurity;
            break;
        }
    }

    if(!pApiSecurity)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(; pApiSecurity; pApiSecurity = pApiSecurity->pNext)
    {
        if(!strcmp(pApiSecurity->pszName, pszApiName))
        {
            break;
        }
    }

    if(!pApiSecurity)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppApiSecurity = pApiSecurity;
cleanup:
    return dwError;

error:
    if(ppApiSecurity)
    {
        *ppApiSecurity = NULL;
    }
    goto cleanup;
}

uint32_t
check_access_uid_gid(
    PPMD_SECURITY_CONTEXT pContext,
    uid_t uid,
    gid_t gid,
    const char *pszModule,
    const char *pszApiName
    )
{
    uint32_t dwError = 0;
    NTSTATUS status = STATUS_SUCCESS;
    PPMD_API_SECURITY pApiSecurity = NULL;
    PACCESS_TOKEN pToken = NULL;
    ACCESS_MASK AccessDesired = FILE_GENERIC_READ;
    ACCESS_MASK AccessMask = 0;

    GENERIC_MAPPING stMapping =
    {
        .GenericRead    = FILE_GENERIC_READ,
        .GenericWrite   = FILE_GENERIC_WRITE,
        .GenericExecute = FILE_GENERIC_EXECUTE,
        .GenericAll     = FILE_ALL_ACCESS
    };


    if(!pContext ||
       IsNullOrEmptyString(pszModule) ||
       IsNullOrEmptyString(pszApiName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = find_module_api(pContext, pszModule, pszApiName, &pApiSecurity);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pApiSecurity->pSecAbs)
    {
        dwError = init_security_abs(pContext, pApiSecurity);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = LwMapSecurityCreateAccessTokenFromUidGid(
                  pContext->pSecContext,
                  &pToken,
                  uid,
                  gid);
    BAIL_ON_PMD_ERROR(dwError);

    if(!RtlAccessCheck(pApiSecurity->pSecAbs,
                      pToken,
                      AccessDesired,
                      0,
                      &stMapping,
                      &AccessMask,
                      &status))
    {
        fprintf(stderr,
                "API Access denied. User: %d, Group: %d, Module: %s Api: %s",
                uid,
                gid,
                pszModule,
                pszApiName);
        dwError = ERROR_PMD_ACCESS_DENIED;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}

void
free_api_security(
    PPMD_API_SECURITY pApiSecurity
    )
{
    if(!pApiSecurity)
    {
        return;
    }
    while(pApiSecurity)
    {
        PPMD_API_SECURITY pTemp = pApiSecurity->pNext;

        PMD_SAFE_FREE_MEMORY(pApiSecurity->pszName);
        PMD_SAFE_FREE_MEMORY(pApiSecurity->pszSDDL);
        PMD_SAFE_FREE_MEMORY(pApiSecurity);

        pApiSecurity = pTemp;
    }
}

void
free_module_security(
    PPMD_MODULE_SECURITY pModuleSecurity
    )
{
    if(!pModuleSecurity)
    {
        return;
    }
    while(pModuleSecurity)
    {
        PPMD_MODULE_SECURITY pTemp = pModuleSecurity->pNext;

        free_api_security(pModuleSecurity->pApiSecurity);
        PMD_SAFE_FREE_MEMORY(pModuleSecurity->pszName);
        PMD_SAFE_FREE_MEMORY(pModuleSecurity);

        pModuleSecurity = pTemp;
    }
}

void
free_security_context(
    PPMD_SECURITY_CONTEXT pContext
    )
{
    if(!pContext)
    {
        return;
    }
    free_module_security(pContext->pModuleSecurity);
    PMD_SAFE_FREE_MEMORY(pContext);
}
