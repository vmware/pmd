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

#pragma once

uint32_t
PMDAllocateMemory(
    size_t size,
    void** ppMemory
    );

uint32_t
PMDGetStringLengthW(
    const wstring_t pwszStr,
    size_t* pLength
    );

uint32_t
PMDAllocateStringWFromA(
    const char* pszSrc,
    wstring_t* ppwszDst
    );

uint32_t
PMDSafeAllocateString(
    const char* pszSrc,
    char** ppszDest
    );

uint32_t
PMDAllocateString(
    const char* pszSrc,
    char** ppszDest
    );

uint32_t
PMDAllocateStringAFromW(
    const wstring_t pwszSrc,
    char**  ppszDst
    );

void
PMDFreeMemory(
    void* pMemory
    );

void
PMDFreeStringArrayWithCount(
    char **ppszArray,
    int nCount
    );

uint32_t
find_in_array(
    char **ppszArray,
    int nCount,
    const char *pszStrToFind
    );

void
PMDFreeStringArray(
    char** ppszArray
    );

uint32_t
PMDAllocateStringPrintf(
    char** ppszDst,
    const char* pszFmt,
    ...
    );

int32_t
PMDStringCompareA(
    const char* pszStr1,
    const char* pszStr2,
    uint32_t bIsCaseSensitive);

//configreader.c
void
print_config_data(
    PCONF_DATA pData
    );

uint32_t
read_config_file_custom(
    const char *pszFile,
    const int nMaxLineLength,
    PFN_CONF_SECTION_CB pfnSectionCB,
    PFN_CONF_KEYVALUE_CB pfnKeyValueCB,
    PCONF_DATA *ppData
    );

uint32_t
read_config_file(
    const char *pszFile,
    const int nMaxLineLength,
    PCONF_DATA *ppData
    );

uint32_t
config_get_section(
    PCONF_DATA pData,
    const char *pszGroup,
    PCONF_SECTION *ppSection
    );

void
free_config_data(
    PCONF_DATA pData
    );

//utils.c
uint32_t
dup_argv(
    int argc,
    char* const* argv,
    char*** argvDup
    );

uint32_t
PMDUtilsFormatSize(
    uint32_t unSize,
    char** ppszFormattedSize
    );

uint32_t
file_read_all_text(
    const char *pszFileName,
    char **ppszText
    );

const char *
ltrim(
    const char *pszStr
    );

const char *
rtrim(
    const char *pszStart,
    const char *pszEnd
    );

uint32_t
do_rtrim(
    const char *pszString,
    char **ppszTrimmedString
    );

uint32_t
count_matches(
    const char *pszString,
    const char *pszFind,
    int *pnCount
    );

uint32_t
string_replace(
    const char *pszString,
    const char *pszFind,
    const char *pszReplace,
    char **ppszResult
    );

uint32_t
make_array_from_string(
    const char *pszString,
    const char *pszSeparator,
    char ***pppszArray,
    int *pnCount
    );

uint32_t
read_password_no_echo(
    char **ppszPassword
    );

uint32_t
run_cmd(
    const char *pszCmd,
    const char *pszCmdToLog
    );

uint32_t
run_cmd_pipe_in(
    const char *pszCmd,
    const char *pszCmdToLog,
    FILE *fpIn
    );

uint32_t
url_decode(
    const char *pszInput,
    char **ppszOutput
    );

int
PMDIsSystemError(
    uint32_t dwError
    );

uint32_t
PMDGetSystemErrorString(
    uint32_t dwSystemError,
    char** ppszError
    );

uint32_t
split_user_and_pass(
    const char* pszUserPass,
    char** ppszUser,
    char** ppszPass
    );

uint32_t
base64_encode(
    const unsigned char* pszInput,
    const size_t nInputLength,
    char** ppszOutput
    );

uint32_t
base64_decode(
    const char *pszInput,
    unsigned char **ppOutBytes,
    int *pnLength
    );

uint32_t
base64_get_user_pass(
    const char *pszBase64,
    char **ppszUser,
    char **ppszPass
    );

uint32_t
validate_cmd(
    const char *pszCmd
    );
uint32_t
isStringPrefix(
        char *pszString,
        char *pszPrefix,
        int *result
   );

//rpcsrvutils.c
uint32_t
PMDRpcServerAllocateMemory(
    size_t size,
    void** ppMemory
    );

uint32_t
PMDRpcServerAllocateStringA(
    const char* pszSource,
    char** ppszTarget
    );

uint32_t
PMDRpcServerAllocateStringW(
    wstring_t pwszSource,
    wstring_t* ppwszTarget
    );

uint32_t
PMDRpcServerAllocateWFromA(
    const char* pszSource,
    wstring_t* ppwszDest
    );

void
PMDRpcServerFreeMemory(
   void* pMemory
   );

//dcerpcerror.c
uint32_t
PMDIsDceRpcError(
    uint32_t dwErrorCode
    );

uint32_t
PMDGetDceRpcErrorString(
    uint32_t dwRpcError,
    char** ppszErrorMessage
    );
