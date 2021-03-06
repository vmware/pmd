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

#include "includes.h"

uint32_t conf_section_default(
    PCONF_DATA pData,
    const char *pszSection
    );

uint32_t conf_keyvalue_default(
    PCONF_DATA pData,
    const char *psKey,
    const char *pszValue
    );

static PFN_CONF_SECTION_CB pfnConfSectionCB = conf_section_default;
static PFN_CONF_KEYVALUE_CB pfnConfKeyValueCB = conf_keyvalue_default;

void
print_config_data(
    PCONF_DATA pData
    )
{
    PCONF_SECTION pSection = NULL;
    PKEYVALUE pKeyValue = NULL;
    if(!pData) return;

    fprintf(stdout, "File: %s\n", pData->pszConfFile);

    pSection = pData->pSections;
    while(pSection)
    {
        fprintf(stdout, "[%s]\n", pSection->pszName);
        pKeyValue = pSection->pKeyValues;
        while(pKeyValue)
        {
            fprintf(stdout, "%s=%s\n", pKeyValue->pszKey, pKeyValue->pszValue);
            pKeyValue = pKeyValue->pNext;
        }
        pSection = pSection->pNext;
    }

}

uint32_t
get_section_boundaries(
    const char *pszLine,
    const char **ppszStart,
    const char **ppszEnd
    )
{
    uint32_t dwError = 0;
    const char *pszStart = NULL;
    const char *pszEnd = NULL;

    pszStart = strchr(pszLine, '[');
    if(!pszStart)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszEnd = strrchr(pszLine, ']');
    if(!pszEnd)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszEnd < pszStart)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszStart = pszStart;
    *ppszEnd = pszEnd;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
get_section(
    const char *pszLine,
    char **ppszSection
    )
{
    uint32_t dwError = 0;
    char *pszSection = NULL;
    const char *pszStart = NULL;
    const char *pszEnd = NULL;

    dwError = get_section_boundaries(pszLine, &pszStart, &pszEnd);
    BAIL_ON_PMD_ERROR(dwError);

    pszStart = ltrim(pszStart + 1);
    pszEnd = rtrim(pszStart, pszEnd - 1);

    pszSection = calloc(pszEnd - pszStart + 2, 1);
    memcpy(pszSection, pszStart, pszEnd - pszStart + 1);

    *ppszSection = pszSection;

cleanup:
    return dwError;

error:
    if(ppszSection)
    {
        *ppszSection = NULL;
    }
    goto cleanup;
}

uint32_t
is_section(
    const char *pszLine,
    int *pnSection
    )
{
    uint32_t dwError = 0;
    const char *pszStart = NULL;
    const char *pszEnd = NULL;

    dwError = get_section_boundaries(pszLine, &pszStart, &pszEnd);
    BAIL_ON_PMD_ERROR(dwError);

    *pnSection = 1;
cleanup:
    return dwError;

error:
    if(pnSection)
    {
        *pnSection = 0;
    }
    if(dwError == ENOENT)
    {
        dwError = 0;
    }
    goto cleanup;
}

void
free_key_values(
    PKEYVALUE pKeyValue
    )
{
    if(!pKeyValue)
    {
        return;
    }
    while(pKeyValue)
    {
        PKEYVALUE pKeyValueTemp = pKeyValue->pNext;
        PMD_SAFE_FREE_MEMORY(pKeyValue->pszKey);
        PMD_SAFE_FREE_MEMORY(pKeyValue->pszValue);
        PMD_SAFE_FREE_MEMORY(pKeyValue);
        pKeyValue = pKeyValueTemp;
    }
}

void
free_config_sections(
    PCONF_SECTION pSection
    )
{
    if(!pSection)
    {
        return;
    }
    while(pSection)
    {
        PCONF_SECTION pSectionTemp = pSection->pNext;
        free_key_values(pSection->pKeyValues);
        PMD_SAFE_FREE_MEMORY(pSection->pszName);
        PMD_SAFE_FREE_MEMORY(pSection);
        pSection = pSectionTemp;
    }
}

void
free_config_data(
    PCONF_DATA pData
    )
{
    PCONF_SECTION pSection = NULL;
    if(!pData)
    {
        return;
    }
    free_config_sections(pData->pSections);
    PMD_SAFE_FREE_MEMORY(pData->pszConfFile);
    PMD_SAFE_FREE_MEMORY(pData);
}

uint32_t
conf_section_default(
    PCONF_DATA pData,
    const char *pszSection
    )
{
    uint32_t dwError = 0;
    PCONF_SECTION pNewSection = NULL;
    PCONF_SECTION pSection = NULL;

    if(!pData || IsNullOrEmptyString(pszSection))
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pSection = pData->pSections;
    while(pSection && pSection->pNext) pSection = pSection->pNext;

    dwError = PMDAllocateMemory(sizeof(CONF_SECTION), (void **)&pNewSection);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszSection, &pNewSection->pszName);
    BAIL_ON_PMD_ERROR(dwError);

    if(pSection)
    {
        pSection->pNext = pNewSection;
    }
    else
    {
        pData->pSections = pNewSection;
    }
    pNewSection = NULL;

cleanup:
    return dwError;

error:
    if(pNewSection)
    {
        free_config_sections(pNewSection);
    }
    goto cleanup;
}

uint32_t
conf_keyvalue_default(
    PCONF_DATA pData,
    const char *pszKey,
    const char *pszValue
    )
{
    uint32_t dwError = 0;
    char *pszEq = NULL;
    PCONF_SECTION pSection = NULL;
    PKEYVALUE pNewKeyValue = NULL;
    PKEYVALUE pKeyValue = NULL;
    const char *pszTemp = NULL;
    const char *pszTempEnd = NULL;

    //Allow for empty values
    if(!pData || IsNullOrEmptyString(pszKey))
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszEq = strchr(pszKey, '=');
    if(!pszEq)
    {
        fprintf(stderr, "keyvalue lines must be of format key=value\n");
        dwError = EDOM;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pSection = pData->pSections;
    for(;pSection && pSection->pNext; pSection = pSection->pNext);

    if(!pSection)
    {
        fprintf(stderr, "conf file must start with a section");
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pKeyValue = pSection->pKeyValues;
    for(;pKeyValue && pKeyValue->pNext; pKeyValue = pKeyValue->pNext);

    pszTemp = rtrim(pszValue, pszEq);
    pNewKeyValue = calloc(sizeof(KEYVALUE), 1);
    pNewKeyValue->pszKey = calloc(pszTemp - pszValue + 1, 1);
    strncpy(pNewKeyValue->pszKey, pszValue, pszTemp - pszValue);

    pszTemp = ltrim(pszEq + 1);
    pszTempEnd = rtrim(pszTemp, pszTemp + strlen(pszTemp) - 1);
    pNewKeyValue->pszValue = calloc(pszTempEnd - pszTemp + 2, 1);
    strncpy(pNewKeyValue->pszValue, pszTemp, pszTempEnd - pszTemp + 1);

    if(pKeyValue) pKeyValue->pNext = pNewKeyValue;
    else pSection->pKeyValues = pNewKeyValue;

cleanup:
    return dwError;

error:
    goto cleanup;
}

void set_config_callbacks(
    PFN_CONF_SECTION_CB pSectionCB,
    PFN_CONF_KEYVALUE_CB pKeyValueCB
    )
{
    pfnConfSectionCB = pSectionCB;
    pfnConfKeyValueCB = pKeyValueCB;
}

uint32_t
read_config_file_custom(
    const char *pszFile,
    const int nLineLength,
    PFN_CONF_SECTION_CB pfnSectionCB,
    PFN_CONF_KEYVALUE_CB pfnKeyValueCB,
    PCONF_DATA *ppData
    )
{
    uint32_t dwError = 0;
    PFN_CONF_SECTION_CB pfnSectionCBDefault = conf_section_default;
    PFN_CONF_KEYVALUE_CB pfnKeyValueCBDefault = conf_keyvalue_default;

    set_config_callbacks(pfnSectionCB, pfnKeyValueCB);
    dwError = read_config_file(pszFile, nLineLength, ppData);
    set_config_callbacks(pfnSectionCBDefault, pfnKeyValueCBDefault);

    return dwError;
}

uint32_t
process_config_line(
    const char *pszLine,
    PCONF_DATA pData
    )
{
    uint32_t dwError = 0;
    int nSection = 0;
    char *pszSection = NULL;

    if(IsNullOrEmptyString(pszLine) || !pData)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = is_section(pszLine, &nSection);
    BAIL_ON_PMD_ERROR(dwError);

    if(nSection && pfnConfSectionCB)
    {
        char *pszSection = NULL;
        dwError = get_section(pszLine, &pszSection);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = pfnConfSectionCB(pData, pszSection);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(pfnConfKeyValueCB)
    {
        if(strchr(pszLine, '='))
        {
            dwError = pfnConfKeyValueCB(pData, pszLine, pszLine);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszSection);
    return dwError;

error:
    goto cleanup;
}

uint32_t
read_config_file(
    const char *pszFile,
    const int nLineLength,
    PCONF_DATA *ppData
    )
{
    uint32_t dwError = 0;
    FILE *fp = NULL;
    char *pszLine = NULL;
    PCONF_DATA pData = NULL;
    int nMaxLineLength = 0;

    if(IsNullOrEmptyString(pszFile) || !ppData)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fp = fopen(pszFile, "r");
    if(!fp)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(CONF_DATA), (void **)&pData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszFile, &pData->pszConfFile);
    BAIL_ON_PMD_ERROR(dwError);

    nMaxLineLength = nLineLength > MAX_CONFIG_LINE_LENGTH ?
                  nLineLength : MAX_CONFIG_LINE_LENGTH;
    dwError = PMDAllocateMemory(nMaxLineLength, (void **)&pszLine);
    BAIL_ON_PMD_ERROR(dwError);

    while(!feof(fp))
    {
        if(fgets(pszLine, nMaxLineLength, fp))
        {
            const char *pszTrimmedLine = ltrim(pszLine);

            //ignore empty lines, comments
            if(IsNullOrEmptyString(pszTrimmedLine) || *pszTrimmedLine == '#')
            {
                continue;
            }
            dwError = process_config_line(pszTrimmedLine, pData);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppData = pData;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszLine);
    if(fp)
    {
        fclose(fp);
    }
    return dwError;

error:
    if(ppData)
    {
        *ppData = NULL;
    }
    free_config_data(pData);
    goto cleanup;
}

uint32_t
config_get_section(
    PCONF_DATA pData,
    const char *pszGroup,
    PCONF_SECTION *ppSection
    )
{
    uint32_t dwError = 0;
    PCONF_SECTION pSections = NULL;
    PCONF_SECTION pSection = NULL;

    if(!pData || IsNullOrEmptyString(pszGroup) || !ppSection)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pSections = pData->pSections;
    for(; pSections; pSections = pSections->pNext)
    {
        if(!strcmp(pszGroup, pSections->pszName))
        {
            pSection = pSections;
            break;
        }
    }

    if(!pSection)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppSection = pSection;

cleanup:
    return dwError;

error:
    if(ppSection)
    {
        *ppSection = NULL;
    }
    goto cleanup;
}
