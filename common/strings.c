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
PMDGetStringLengthW(
    const wstring_t pwszStr,
    size_t* pLength
    )
{
    ULONG dwError = 0;

    if (!pwszStr || !pLength)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    else
    {
        *pLength = LwRtlWC16StringNumChars(pwszStr);
    }

    return dwError;
}

uint32_t
PMDAllocateStringWFromA(
    const char* pszSrc,
    wstring_t* ppwszDst
    )
{
    uint32_t dwError = 0;

    if (!pszSrc || !ppwszDst)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    else
    {
        dwError = LwNtStatusToWin32Error(
                        LwRtlWC16StringAllocateFromCString(ppwszDst, pszSrc));
    }

    return dwError;
}

uint32_t
PMDAllocateStringAFromW(
    const wstring_t pwszSrc,
    char**  ppszDst
    )
{
    uint32_t dwError = 0;

    if (!pwszSrc || !ppszDst)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    else
    {
        dwError = LwNtStatusToWin32Error(
                        LwRtlCStringAllocateFromWC16String(ppszDst, pwszSrc));
    }

    return dwError;
}

uint32_t
PMDAllocateString(
    const char* pszSrc,
    char** ppszDest
    )
{
    uint32_t dwError = 0;
    char* pszDest = NULL;

    if (!pszSrc || !ppszDest)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszDest = strdup(pszSrc);
    *ppszDest = pszDest;

cleanup:
    return dwError;

error:
    if(ppszDest)
    {
        *ppszDest = NULL;
    }
    goto cleanup;
}

void
PMDFreeStringArrayWithCount(
    char **ppszArray,
    int nCount
    )
{
    char** ppszTemp = NULL;
    if(ppszArray)
    {
        while(nCount)
        {
            PMDFreeMemory(ppszArray[--nCount]);
        }
        PMDFreeMemory(ppszArray);
    }
}

void
PMDFreeStringArray(
    char** ppszArray
    )
{
    char** ppszTemp = NULL;
    if(ppszArray)
    {
        ppszTemp = ppszArray;
        while(ppszTemp && *ppszTemp)
        {
            PMDFreeMemory(*ppszTemp);
            ++ppszTemp;
        }
        PMDFreeMemory(ppszArray);
    }
}

uint32_t
PMDAllocateStringPrintf(
    char** ppszDst,
    const char* pszFmt,
    ...
    )
{
    uint32_t dwError = 0;
    size_t nSize = 0;
    char* pszDst = NULL;
    char chDstTest = '\0';
    va_list argList;

    if(!ppszDst || !pszFmt)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    //Find size
    va_start(argList, pszFmt);
    nSize = vsnprintf(&chDstTest, 1, pszFmt, argList);
    va_end(argList);

    if(nSize <= 0)
    {
        dwError = errno;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nSize = nSize + 1;
    dwError = PMDAllocateMemory(nSize, (void**)&pszDst);
    BAIL_ON_PMD_ERROR(dwError);

    va_start(argList, pszFmt);
    nSize = vsnprintf(pszDst, nSize, pszFmt, argList);
    va_end(argList);

    if(nSize <= 0)
    {
        dwError = errno;
        BAIL_ON_PMD_ERROR(dwError);
    }
    *ppszDst = pszDst;
cleanup:
    return dwError;

error:
    if(ppszDst)
    {
        *ppszDst = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszDst);
    goto cleanup;
}

int32_t
PMDStringCompareA(
    const char* pszStr1,
    const char* pszStr2,
    uint32_t bIsCaseSensitive
    )
{
    return LwRtlCStringCompare(pszStr1, pszStr2, bIsCaseSensitive);
}

uint32_t
find_in_array(
    char **ppszArray,
    int nCount,
    const char *pszStrToFind
    )
{
    uint32_t dwError = 0;
    if(!ppszArray || nCount <= 0 || IsNullOrEmptyString(pszStrToFind))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = ENOENT;
    while(nCount > 0)
    {
        if(!strcmp(pszStrToFind, ppszArray[--nCount]))
        {
            dwError = 0;
            break;
        }
    }

cleanup:
    return dwError;

error:
    goto cleanup;
}
