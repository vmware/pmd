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
PPMDGetHostName(
    char** ppszHostName
)
{
    uint32_t dwError = 0;
    char pszHostBuf[HOST_NAME_MAX];
    uint32_t dwBufLen = sizeof(pszHostBuf) - 1;
    char* pszHostName = NULL;

    if (gethostname(pszHostBuf, dwBufLen) < 0)
    {
        dwError = errno;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszHostBuf, &pszHostName);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszHostName = pszHostName;

cleanup:
    return dwError;

error:
    if(ppszHostName)
    {
        *ppszHostName = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszHostName);
    goto cleanup;
}

uint32_t
PPMDGetCanonicalHostName(
    char* pszHostname,
    char** ppszCanonicalHostname
    )
{
    uint32_t  dwError = 0;
    struct addrinfo* pHostInfo = NULL;
    char szCanonicalHostname[NI_MAXHOST+1] = "";
    char*   pszCanonicalHostname = NULL;
    struct addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_flags = AI_CANONNAME;

    dwError = getaddrinfo(
                      pszHostname,
                      NULL,
                      &hints,
                      &pHostInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = getnameinfo(
                      pHostInfo->ai_addr,
                      (socklen_t)(pHostInfo->ai_addrlen),
                      szCanonicalHostname,
                      NI_MAXHOST,
                      NULL,
                      0,
                      NI_NAMEREQD);
    BAIL_ON_PMD_ERROR(dwError);

    if (!IsNullOrEmptyString(&szCanonicalHostname[0]))
    {
        dwError = PMDAllocateString(
                    &szCanonicalHostname[0],
                    &pszCanonicalHostname);
    }
    else
    {
        dwError = ERROR_NO_DATA;
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppszCanonicalHostname = pszCanonicalHostname;

cleanup:

    if (pHostInfo)
    {
        freeaddrinfo(pHostInfo);
    }

    return dwError;

error:

    *ppszCanonicalHostname = NULL;

    PMD_SAFE_FREE_MEMORY(pszCanonicalHostname);

    goto cleanup;
}

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

uint32_t
split_user_and_pass(
    const char* pszUserPass,
    char** ppszUser,
    char** ppszPass
    )
{
    uint32_t dwError = 0;
    char* pszUser = NULL;
    char* pszPass = NULL;
    char* pszSeparator = NULL;
    char SEPARATOR = ':';
    int nLength = 0;

    if(IsNullOrEmptyString(pszUserPass) || !ppszUser || !ppszPass)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pszSeparator = strchr(pszUserPass, SEPARATOR);
    if(!pszSeparator)
    {
        dwError = ERROR_PMD_USER_PASS_FORMAT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nLength = pszSeparator - pszUserPass;
    dwError = PMDAllocateMemory(nLength + 1, (void **)&pszUser);
    BAIL_ON_PMD_ERROR(dwError);

    strncpy(pszUser, pszUserPass, nLength);

    nLength = strlen(pszUserPass) - (nLength + 1);
    dwError = PMDAllocateMemory(nLength + 1, (void **)&pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    strncpy(pszPass, pszSeparator+1, nLength);

    *ppszUser = pszUser;
    *ppszPass = pszPass;

cleanup:
    return dwError;

error:
    if(ppszUser)
    {
        *ppszUser = NULL;
    }
    if(ppszPass)
    {
        *ppszPass = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    goto cleanup;
}

void
pmd_free_server_env(
    PSERVER_ENV pEnv
    )
{
    if(!pEnv)
    {
        return;
    }
    pthread_mutex_destroy(&gpServerEnv->mutexModuleEntries);
    pthread_mutex_destroy(&gpServerEnv->mutexPkgMgmtApi);
    pmd_free_config(gpServerEnv->pConfig);
    coapi_free_api_def(gpServerEnv->pApiDef);
    PMD_SAFE_FREE_MEMORY(gpServerEnv->pRestProcessor);
    free_security_context(gpServerEnv->pSecurityContext);
}
