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


#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "pmdtypes.h"
#include "pmderror.h"

uint32_t
rpc_open(
    const char *module,
    const char *pszServer,
    const char *pszUser,
    const char *pszDomain,
    const char *pszPass,
    const char *spn,
    PPMDHANDLE *phHandle
    );

//pmd interface
uint32_t
pmd_server_type(
    PPMDHANDLE hHandle,
    uint32_t *pdwServerType
    );

//rpmostree interface
uint32_t
rpmostree_server_info(
    PPMDHANDLE hHandle,
    PPMD_RPMOSTREE_SERVER_INFO_A *ppInfo
    );

uint32_t
rpmostree_client_info(
    PPMDHANDLE hHandle,
    PPMD_RPMOSTREE_CLIENT_INFO_A *ppInfo
    );

uint32_t
rpmostree_client_syncto(
    PPMDHANDLE hHandle,
    const char *pszHash
    );

//demo
uint32_t
demo_client_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

uint32_t
demo_client_isprime(
    PPMDHANDLE hHandle,
    int nNumToCheck,
    int *pnIsPrime
    );

uint32_t
demo_client_primes(
    PPMDHANDLE hHandle,
    int nStart,
    int nCount,
    int **ppPrimes,
    int *pnPrimeCount
    );

uint32_t
PMDFreeHandle(
    PPMDHANDLE hHandle
    );

uint32_t
PMDGetErrorString(
    uint32_t dwErrorCode,
    char **ppszErrorString
    );

void
rpmostree_free_server_info(
    PPMD_RPMOSTREE_SERVER_INFO_A pInfoA
    );

void
rpmostree_free_client_info(
    PPMD_RPMOSTREE_CLIENT_INFO_A pInfoA
    );

#ifdef __cplusplus
}
#endif
