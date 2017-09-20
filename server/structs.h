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

struct _PMD_SECURITY_CONTEXT_;
typedef struct _PMD_SECURITY_CONTEXT_ *PPMD_SECURITY_CONTEXT;

typedef struct _PMD_REST_CONFIG_
{
    int nEnabled;
    int nPort;
    int nUseKerberos;
    char *pszApiSpec;
}PMD_REST_CONFIG, *PPMD_REST_CONFIG;

typedef struct _PMD_CONFIG_
{
    int nServerType;
    char* pszCurrentHash;
    char* pszServerUrl;
    char* pszComposeServer;
    char *pszApiSecurityConf;
    PPMD_REST_CONFIG pRestConfig;
    char *pszPrivsepPubKeyFile;
}PMD_CONFIG, *PPMD_CONFIG;

typedef struct _SERVER_ENV_
{
    pthread_mutex_t mutexModuleEntries;
    PPMD_CONFIG pConfig;
    PREST_API_DEF pApiDef;
    PREST_MODULE_ENTRY pModuleEntries;
    PREST_PROCESSOR pRestProcessor;
    PPMD_SECURITY_CONTEXT pSecurityContext;
    PVMREST_HANDLE pRestHandle;
}SERVER_ENV, *PSERVER_ENV;
