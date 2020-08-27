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

size_t
PMDWC16StringNumChars(
        wchar16_t const *pszString
    )
{
    size_t len = 0;

    if (pszString)
    {
        for(; pszString[len] != 0; len++);
    }
    return len;
}

uint32_t
PMDConvertStringToWC16(
    wchar16_t **ppwszDest,
    const char *pszSrc
    )
{
    iconv_t cd = 0;
    size_t nconv = 0, insize = 0, mbLen = 0, mbSize = 0;
    char *inputString = NULL;
    char *wcharString = NULL;
    wchar16_t *pwszbuf = NULL;
    uint32_t dwError = 0;

    if (!ppwszDest || !pszSrc)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    cd = iconv_open ("UCS-2LE", "");
    if (cd == (iconv_t)-1)
    {
        dwError = ERROR_PMD_CONVERT_TO_WCHAR_FAILED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    mbLen = mbstowcs (NULL, pszSrc, 0);
    if (mbLen == -1)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    mbSize = (mbLen + 1) * sizeof (wchar16_t);
    dwError = PMDAllocateMemory (mbSize, (void**)&pwszbuf);
    BAIL_ON_PMD_ERROR(dwError);

    inputString = (char *)pszSrc;
    wcharString = (char *)pwszbuf;
    insize = strlen (pszSrc) * sizeof (char);

    nconv = iconv (cd, &inputString, &insize, &wcharString, &mbSize);
    if (nconv == -1)
    {
        dwError = ERROR_PMD_CONVERT_TO_WCHAR_FAILED;
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (mbSize >= sizeof (wchar16_t))
    {
        *(wchar16_t *)wcharString = 0;
    }
    *ppwszDest = pwszbuf;
cleanup:
    if (cd && (cd != (iconv_t)-1))
    {
        iconv_close(cd);
    }
    return dwError;

error:
    if (pwszbuf)
    {
        free(pwszbuf);
    }
    if (ppwszDest)
    {
        *ppwszDest = 0;
    }
    goto cleanup;

}

uint32_t
PMDConvertWC16ToString(
    char **ppszDest,
    const wchar16_t *pwszSrc
    )
{
    iconv_t cd = 0;
    size_t nconv = 0, avail = 0, insize = 0;
    char *wcharString = NULL;
    char *pszbuf = NULL;
    char *outputString = NULL;
    uint32_t dwError = 0;

    if (!ppszDest || !pwszSrc)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    cd = iconv_open ("", "UCS-2LE");
    if (cd == (iconv_t)-1)
    {
        dwError = ERROR_PMD_CONVERT_TO_WCHAR_FAILED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    insize = PMDWC16StringNumChars(pwszSrc) * sizeof(wchar16_t);

    dwError = PMDAllocateMemory((insize + 1) * sizeof(char), (void **)&pszbuf);
    BAIL_ON_PMD_ERROR(dwError);

    wcharString = (char *)pwszSrc;
    outputString = (char *)pszbuf;
    avail = insize + 1; /* Added one for terminating with NULL */

    nconv = iconv (cd, &wcharString, &insize, &outputString, &avail);
    if (nconv == -1)
    {
        dwError = ERROR_PMD_CONVERT_TO_WCHAR_FAILED;
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (avail >= sizeof(wchar16_t))
    {
        *outputString = 0;
    }

    *ppszDest = pszbuf;
cleanup:
    if (cd && (cd != (iconv_t)-1))
    {
        iconv_close(cd);
    }
    return dwError;

error:
    if (pszbuf)
    {
        free(pszbuf);
    }
    if (ppszDest)
    {
        *ppszDest = 0;
    }
    goto cleanup;
}

uint32_t
PMDSafeAllocateString(
    const char *pszSrc,
    char **ppszDest
    )
{
    if(!pszSrc && ppszDest)
    {
        *ppszDest = NULL;
        return 0;
    }
    return PMDAllocateString(pszSrc, ppszDest);
}

uint32_t
PMDGetStringLengthW(
    const wstring_t pwszStr,
    size_t* pLength
    )
{
    uint32_t dwError = 0;

    if (!pwszStr || !pLength)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    else
    {
        *pLength = PMDWC16StringNumChars(pwszStr);
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
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = PMDConvertStringToWC16(ppwszDst, pszSrc);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
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
        dwError = PMDConvertWC16ToString(ppszDst, pwszSrc);
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
