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
base64_encode(
    const unsigned char* pszInput,
    const size_t nInputLength,
    char** ppszOutput
    )
{
    uint32_t dwError = 0;
    char* pszOutput = NULL;
    int nLength = 0;
    BIO* pBio64 = NULL;
    BIO* pBioMem = NULL;
    BUF_MEM *pMemOut = NULL;

    if(!pszInput || !ppszOutput)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pBio64 = BIO_new(BIO_f_base64());
    pBioMem = BIO_new(BIO_s_mem());
    pBioMem = BIO_push(pBio64, pBioMem);
    BIO_set_flags(pBioMem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(pBioMem, BIO_CLOSE);

    if(BIO_write(pBioMem, pszInput, nInputLength) <= 0)
    {
        dwError = ERROR_PMD_BASE64_ENCODE;
        BAIL_ON_PMD_ERROR(dwError);
    }
    BIO_flush(pBioMem);
    BIO_get_mem_ptr(pBioMem, &pMemOut);

    dwError = PMDAllocateMemory(pMemOut->length + 1, (void **)&pszOutput);
    BAIL_ON_PMD_ERROR(dwError);

    memcpy(pszOutput, pMemOut->data, pMemOut->length);

    *ppszOutput = pszOutput;

cleanup:
    if(pBioMem)
    {
        BIO_free_all(pBioMem);
    }
    return dwError;

error:
    if(ppszOutput)
    {
        *ppszOutput = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutput);
    goto cleanup;
}

uint32_t
base64_decode(
    const char* pszInput,
    char** ppszOutput,
    int *pnLength
    )
{
    uint32_t dwError = 0;
    char* pszOutput = NULL;
    int nLength = 0;
    int nInputLength = 0;
    BIO* pBio64 = NULL;
    BIO* pBioMem = NULL;
    char *pszModInput = NULL;
    const char *pszTempInput = pszInput;
    int nPaddingRequired = 0;

    if(!pszInput || !ppszOutput)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nInputLength = strlen(pszInput);
    nPaddingRequired = nInputLength % 4;
    if(nPaddingRequired == 1)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }
    nPaddingRequired = nPaddingRequired == 3 ? 1 : nPaddingRequired;
    nLength = nInputLength + nPaddingRequired;

    if(nPaddingRequired)
    {
        char pszPadding[3] = {0};
        while(--nPaddingRequired >= 0)
        {
            pszPadding[nPaddingRequired] = '=';
        }
        dwError = PMDAllocateStringPrintf(&pszModInput,
                                          "%s%s",
                                          pszInput,
                                          pszPadding);
        BAIL_ON_PMD_ERROR(dwError);

        pszTempInput = pszModInput;
    }

    dwError = PMDAllocateMemory(nLength + 1, (void **)&pszOutput);
    BAIL_ON_PMD_ERROR(dwError);

    pBio64 = BIO_new(BIO_f_base64());
    pBioMem = BIO_new_mem_buf((char*)pszTempInput, -1);
    pBioMem = BIO_push(pBio64, pBioMem);
    BIO_set_flags(pBioMem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(pBioMem, BIO_CLOSE);

    nLength = BIO_read(pBioMem, pszOutput, nLength - nPaddingRequired);
    if(nLength <= 0)
    {
        dwError = ERROR_PMD_BASE64_DECODE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszOutput = pszOutput;
    *pnLength = nLength;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszModInput);
    if(pBioMem)
    {
        BIO_free_all(pBioMem);
    }
    return dwError;

error:
    if(ppszOutput)
    {
        *ppszOutput = NULL;
    }
    if(pnLength)
    {
        *pnLength = 0;
    }
    PMD_SAFE_FREE_MEMORY(pszOutput);
    goto cleanup;
}
