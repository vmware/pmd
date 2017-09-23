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
dup_argv(
    int argc,
    char* const* argv,
    char*** argvDup
    )
{
    uint32_t dwError = 0;
    int i = 0;
    char** dup = NULL;

    if(!argv || !argvDup)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(char*) * argc, (void**)&dup);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0; i < argc; ++i)
    {
        dup[i] = strdup(argv[i]);
    }
    *argvDup = dup;

cleanup:
    return dwError;

error:
    if(argvDup)
    {
        *argvDup = NULL;
    }
    goto cleanup;
}

uint32_t
PMDUtilsFormatSize(
    uint32_t unSize,
    char** ppszFormattedSize
    )
{
    uint32_t dwError = 0;
    char* pszFormattedSize = NULL;
    char* pszSizes = "bkMG";
    double dSize = unSize;

    int nIndex = 0;
    int nLimit = strlen(pszSizes);
    double dKiloBytes = 1024.0;
    int nMaxSize = 25;

    if(!ppszFormattedSize)
    {
      dwError = ERROR_PMD_INVALID_PARAMETER;
      BAIL_ON_PMD_ERROR(dwError);
    }

    while(nIndex < nLimit && dSize > dKiloBytes)
    {
        dSize /= dKiloBytes;
        nIndex++;
    }

    dwError = PMDAllocateMemory(nMaxSize, (void**)&pszFormattedSize);
    BAIL_ON_PMD_ERROR(dwError);

    if(sprintf(pszFormattedSize, "%.2f %c", dSize, pszSizes[nIndex]) < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszFormattedSize = pszFormattedSize;

cleanup:
    return dwError;

error:
    if(ppszFormattedSize)
    {
        *ppszFormattedSize = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszFormattedSize);
    goto cleanup;
}

uint32_t
file_read_all_text(
    const char *pszFileName,
    char **ppszText
    )
{
    uint32_t dwError = 0;
    FILE *fp = NULL;
    char *pszText = NULL;
    int nLength = 0;
    int nBytesRead = 0;

    if(!pszFileName || !ppszText)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fp = fopen(pszFileName, "r");
    if(!fp)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }
    fseek(fp, 0, SEEK_END);
    nLength = ftell(fp);

    dwError = PMDAllocateMemory(nLength + 1, (void **)&pszText);
    BAIL_ON_PMD_ERROR(dwError);

    if(fseek(fp, 0, SEEK_SET))
    {
        dwError = errno;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nBytesRead = fread(pszText, 1, nLength, fp);
    if(nBytesRead != nLength)
    {
        dwError = EBADFD;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszText = pszText;
cleanup:
    if(fp)
    {
        fclose(fp);
    }
    return dwError;

error:
    if(ppszText)
    {
        *ppszText = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszText);
    goto cleanup;
}

const char *
ltrim(
    const char *pszStr
    )
{
    if(!pszStr) return NULL;
    while(isspace(*pszStr)) ++pszStr;
    return pszStr;
}

const char *
rtrim(
    const char *pszStart,
    const char *pszEnd
    )
{
    if(!pszStart || !pszEnd) return NULL;
    while(pszEnd > pszStart && isspace(*pszEnd)) pszEnd--;
    return pszEnd;
}

uint32_t
do_rtrim(
    const char *pszString,
    char **ppszTrimmedString
    )
{
    uint32_t dwError = 0;
    char *pszTrimmedString = NULL;
    const char *pszEnd = NULL;
    int nLength = 0;

    if(IsNullOrEmptyString(pszString) || !ppszTrimmedString)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszEnd = rtrim(pszString, pszString + (strlen(pszString)));

    nLength = pszEnd - pszString;

    if(nLength < 0)
    {
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(nLength + 1, (void **)&pszTrimmedString);
    BAIL_ON_PMD_ERROR(dwError);

    strncpy(pszTrimmedString, pszString, nLength);

    *ppszTrimmedString = pszTrimmedString;

cleanup:
    return dwError;

error:
    if(ppszTrimmedString)
    {
        *ppszTrimmedString = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszTrimmedString);
    goto cleanup;
}

uint32_t
count_matches(
    const char *pszString,
    const char *pszFind,
    int *pnCount
    )
{
    uint32_t dwError = 0;
    int nCount = 0;
    int nOffset = 0;
    int nFindLength = 0;
    char *pszMatch = NULL;

    if(IsNullOrEmptyString(pszString) ||
       IsNullOrEmptyString(pszFind) ||
       !pnCount)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nFindLength = strlen(pszFind);
    while((pszMatch = strcasestr(pszString + nOffset, pszFind)))
    {
        ++nCount;
        nOffset = pszMatch - pszString + nFindLength;
    }

    *pnCount = nCount;
cleanup:
    return dwError;

error:
    if(pnCount)
    {
        *pnCount = 0;
    }
    goto cleanup;
}

uint32_t
string_replace(
    const char *pszString,
    const char *pszFind,
    const char *pszReplace,
    char **ppszResult
    )
{
    uint32_t dwError = 0;
    char *pszResult = NULL;
    char *pszBoundary = NULL;
    int nCount = 0;
    int nResultLength = 0;
    int nFindLength = 0;
    int nReplaceLength = 0;
    int nOffset = 0;

    if(IsNullOrEmptyString(pszString) ||
       IsNullOrEmptyString(pszFind) ||
       !ppszResult)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = count_matches(pszString, pszFind, &nCount);
    BAIL_ON_PMD_ERROR(dwError);

    if(nCount == 0)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nFindLength = strlen(pszFind);
    if(pszReplace)
    {
        nReplaceLength = strlen(pszReplace);
    }

    nResultLength = strlen(pszString) +
                    nCount * (nReplaceLength - nFindLength);

    dwError = PMDAllocateMemory(sizeof(char) * (nResultLength + 1),
                                (void **)&pszResult);
    BAIL_ON_PMD_ERROR(dwError);

    nOffset = 0;
    while((pszBoundary = strcasestr(pszString + nOffset, pszFind)))
    {
        int nLength = pszBoundary - (pszString + nOffset);

        strncat(pszResult, pszBoundary - nLength, nLength);
        if(pszReplace)
        {
            strcat(pszResult, pszReplace);
        }

        nOffset = pszBoundary - pszString + nFindLength;
    }

    strcat(pszResult, pszString + nOffset);

    *ppszResult = pszResult;
cleanup:
    return dwError;

error:
    if(ppszResult)
    {
        *ppszResult = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszResult);
    goto cleanup;
}

uint32_t
make_array_from_string(
    const char *pszString,
    const char *pszSeparator,
    char ***pppszArray,
    int *pnCount
    )
{
    uint32_t dwError = 0;
    char **ppszArray = NULL;
    char *pszBoundary = NULL;
    int nOffset = 0;
    int nSepLength = 0;
    int nCount = 1;
    int nIndex = 0;

    if(IsNullOrEmptyString(pszString) ||
       IsNullOrEmptyString(pszSeparator) ||
       !pppszArray ||
       !pnCount)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = count_matches(pszString, pszSeparator, &nCount);
    BAIL_ON_PMD_ERROR(dwError);

    ++nCount;

    dwError = PMDAllocateMemory(sizeof(char **) * (nCount),
                                (void **)&ppszArray);
    BAIL_ON_PMD_ERROR(dwError);

    nOffset = 0;
    nIndex = 0;
    nSepLength = strlen(pszSeparator);
    while((pszBoundary = strcasestr(pszString + nOffset, pszSeparator)))
    {
        int nLength = pszBoundary - (pszString + nOffset);
        dwError = PMDAllocateMemory(sizeof(char) * (nLength + 1),
                                    (void **)&ppszArray[nIndex]);
        BAIL_ON_PMD_ERROR(dwError);

        memcpy(ppszArray[nIndex], pszString + nOffset, nLength);

        nOffset = pszBoundary - pszString + nSepLength;
        ++nIndex;
    }

    dwError = PMDAllocateString(pszString + nOffset, &ppszArray[nIndex]);
    BAIL_ON_PMD_ERROR(dwError);

    *pppszArray = ppszArray;
    *pnCount = nCount;
cleanup:
    return dwError;

error:
    if(pppszArray)
    {
        *pppszArray = NULL;
    }
    if(pnCount)
    {
        *pnCount = 0;
    }
    PMDFreeStringArrayWithCount(ppszArray, nCount);
    goto cleanup;
}

uint32_t
read_password_no_echo(
    char **ppszPassword
    )
{
    uint32_t dwError = 0;
    char pszPasswordBuff[100] = {0};
    char *pszPassword = NULL;
    struct termios tp = {0};
    struct termios save = {0};
    int nLength = 0;

    if(!ppszPassword)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fflush(stdout);

    tcgetattr(0, &tp) ;
    memcpy (&save, &tp, sizeof (struct termios));
    save.c_lflag &= ~ECHO;                /* ECHO off, other bits unchanged */
    tcsetattr(0, TCSANOW, &save);

    if (!fgets(pszPasswordBuff, 100, stdin) && ferror(stdin))
    {
        dwError = ferror(stdin);
        BAIL_ON_PMD_ERROR (dwError);
    }

    nLength = strlen(pszPasswordBuff);
    if(nLength <= 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszPasswordBuff[nLength - 1] == '\n')
    {
        pszPasswordBuff[nLength - 1] = '\0';
    }

    dwError = PMDAllocateString(pszPasswordBuff, &pszPassword);
    BAIL_ON_PMD_ERROR (dwError);

    *ppszPassword = pszPassword;

cleanup:
    tcsetattr(0, TCSANOW, &tp);
    fflush (stdin);
    return dwError;

error:
    if (ppszPassword)
    {
        *ppszPassword = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszPassword);
    goto cleanup;
}

uint32_t
run_cmd(
    const char *pszCmd,
    const char *pszCmdToLog
    )
{
    uint32_t dwError = 0;
    if(IsNullOrEmptyString(pszCmd) || IsNullOrEmptyString(pszCmdToLog))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fprintf(stdout, "Executing command: %s\n", pszCmdToLog);

    dwError = system(pszCmd);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    if(!IsNullOrEmptyString(pszCmdToLog))
    {
        fprintf(stderr, "There was an error executing: %s", pszCmdToLog);
    }
    goto cleanup;
}

uint32_t
run_cmd_pipe_in(
    const char *pszCmd,
    const char *pszCmdToLog,
    FILE *fpIn
    )
{
    uint32_t dwError = 0;
    FILE *fpOut = NULL;
    char pszLine[MAX_LINE_LENGTH] = {0};

    if(IsNullOrEmptyString(pszCmd) || IsNullOrEmptyString(pszCmdToLog) || !fpIn)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fprintf(stdout, "Executing command: %s\n", pszCmdToLog);

    if(!(fpOut = popen(pszCmd, "w")))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = fseek(fpIn, SEEK_SET, 0);
    BAIL_ON_PMD_ERROR(dwError);

    while(fgets(pszLine, MAX_LINE_LENGTH, fpIn))
    {
        fputs(pszLine, fpOut);
    }

cleanup:
    if(fpOut)
    {
        pclose(fpOut);
    }
    return dwError;

error:
    if(!IsNullOrEmptyString(pszCmdToLog))
    {
        fprintf(stderr, "There was an error executing: %s", pszCmdToLog);
    }
    goto cleanup;
}

uint32_t
url_decode(
    const char *pszInput,
    char **ppszOutput
    )
{
    uint32_t dwError = 0;
    char *pszOutput = NULL;
    char *pszCurlOut = NULL;
    CURL *pCurl = NULL;
    int nOutLen = 0;

    if(IsNullOrEmptyString(pszInput) || !ppszOutput)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pCurl = curl_easy_init();
    if(!pCurl)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszCurlOut = curl_easy_unescape(pCurl, pszInput, strlen(pszInput), &nOutLen);
    if(IsNullOrEmptyString(pszCurlOut))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszCurlOut, &pszOutput);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszOutput = pszOutput;

cleanup:
    if(pszCurlOut)
    {
        curl_free(pszCurlOut);
    }
    if(pCurl)
    {
        curl_easy_cleanup(pCurl);
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
PMDGetErrorString(
    uint32_t dwErrorCode,
    char** ppszError
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;
    char* pszSystemError = NULL;
    int i = 0;
    int nCount = 0;
    uint32_t dwActualError = 0;

    //Allow mapped error strings to override
    PMD_ERROR_DESC arErrorDesc[] = PMD_ERROR_TABLE;

    nCount = sizeof(arErrorDesc)/sizeof(arErrorDesc[0]);

    for(i = 0; i < nCount; i++)
    {
        if (dwErrorCode == arErrorDesc[i].nCode)
        {
            dwError = PMDAllocateString(arErrorDesc[i].pszDesc, &pszError);
            BAIL_ON_PMD_ERROR(dwError);
            break;
        }
    }


    //Get system error
    if(!pszError && PMDIsDceRpcError(dwErrorCode))
    {
        dwError = PMDGetDceRpcErrorString(dwErrorCode, &pszError);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else if(!pszError && PMDIsSystemError(dwErrorCode))
    {
        dwError = PMDGetSystemErrorString(dwErrorCode, &pszError);
        BAIL_ON_PMD_ERROR(dwError);
    }

    //If the above attempts did not yield an error string,
    //do default unknown error.
    if(!pszError)
    {
        dwError = PMDAllocateString(PMD_UNKNOWN_ERROR_STRING, &pszError);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszError = pszError;
cleanup:
    return dwError;

error:
    if(ppszError)
    {
        *ppszError = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszError);
    goto cleanup;
}

int
PMDIsSystemError(
    uint32_t dwError
    )
{
    return dwError >= ERROR_PMD_SYSTEM_BASE &&
           dwError <= ERROR_PMD_SYSTEM_END;
}

uint32_t
PMDGetSystemErrorString(
    uint32_t dwSystemError,
    char** ppszError
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;
    char* pszSystemError = NULL;

    if(!ppszError || !PMDIsSystemError(dwSystemError))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(PMDIsSystemError(dwSystemError))
    {
        dwSystemError = dwSystemError - ERROR_PMD_SYSTEM_BASE;
        pszSystemError = strerror(dwSystemError);
        if(pszSystemError)
        {
            dwError = PMDAllocateString(pszSystemError, &pszError);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
    *ppszError = pszError;
cleanup:
    return dwError;
error:
    PMD_SAFE_FREE_MEMORY(pszError);
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
    const char *pszInput,
    unsigned char **ppOutBytes,
    int *pnLength
    )
{
    uint32_t dwError = 0;
    unsigned char *pOutBytes = NULL;
    int nLength = 0;
    int nInputLength = 0;
    BIO* pBio64 = NULL;
    BIO* pBioMem = NULL;
    char *pszModInput = NULL;
    const char *pszTempInput = pszInput;
    int nPaddingRequired = 0;

    if(!pszInput || !ppOutBytes)
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

    dwError = PMDAllocateMemory(nLength + 1, (void **)&pOutBytes);
    BAIL_ON_PMD_ERROR(dwError);

    pBio64 = BIO_new(BIO_f_base64());
    pBioMem = BIO_new_mem_buf((char*)pszTempInput, -1);
    pBioMem = BIO_push(pBio64, pBioMem);
    BIO_set_flags(pBioMem, BIO_FLAGS_BASE64_NO_NL);
    BIO_set_close(pBioMem, BIO_CLOSE);

    nLength = BIO_read(pBioMem, pOutBytes, nLength - nPaddingRequired);
    if(nLength <= 0)
    {
        dwError = ERROR_PMD_BASE64_DECODE;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppOutBytes = pOutBytes;
    *pnLength = nLength;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszModInput);
    if(pBioMem)
    {
        BIO_free_all(pBioMem);
    }
    return dwError;

error:
    if(ppOutBytes)
    {
        *ppOutBytes = NULL;
    }
    if(pnLength)
    {
        *pnLength = 0;
    }
    PMD_SAFE_FREE_MEMORY(pOutBytes);
    goto cleanup;
}

uint32_t
base64_get_user_pass(
    const char *pszBase64,
    char **ppszUser,
    char **ppszPass
    )
{
    uint32_t dwError = 0;
    int nLength = 0;
    char *pszUserPass = NULL;
    char *pszUser = NULL;
    char *pszPass = NULL;

    if(IsNullOrEmptyString(pszBase64) || !ppszUser || !ppszPass)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = base64_decode(
                  pszBase64,
                  (unsigned char **)&pszUserPass,
                  &nLength);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = split_user_and_pass(pszUserPass, &pszUser, &pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszUser = pszUser;
    *ppszPass = pszPass;
cleanup:
    PMD_SAFE_FREE_MEMORY(pszUserPass);
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
