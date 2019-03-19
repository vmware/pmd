/*
 * Copyright © 2019 VMware, Inc.  All Rights Reserved.
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

#include <stdint.h>//for uint32_t

#define PMD_ROLE_PLUGIN_VERSION_MAJOR   "0"
#define PMD_ROLE_PLUGIN_VERSION_MINOR   "0"
#define PMD_ROLE_PLUGIN_VERSION_RELEASE "1"

typedef struct _PMD_ROLE_HANDLE_ *PPMD_ROLE_HANDLE;

typedef enum
{
    ROLE_OPERATION_NONE,
    ROLE_OPERATION_ENABLE,
    ROLE_OPERATION_UPDATE,
    ROLE_OPERATION_REMOVE,
    ROLE_OPERATION_MAX
}PMD_ROLE_OPERATION;

typedef enum
{
    ROLE_STATUS_NONE,
    ROLE_STATUS_SUCCESS,
    ROLE_STATUS_FAILURE,
    ROLE_STATUS_NOT_STARTED,
    ROLE_STATUS_IN_PROGRESS
}PMD_ROLE_STATUS;

typedef struct _PMD_ROLE_PREREQ_
{
    char *pszName;
    char *pszDescription;
}PMD_ROLE_PREREQ, *PPMD_ROLE_PREREQ;

typedef struct _PMD_ROLE_ERROR_
{
    uint32_t dwError;    //Error code
    char *pszError;      //Error string
    char *pszSuggestions; //Suggestions to recover
}PMD_ROLE_ERROR, *PPMD_ROLE_ERROR;

typedef struct _PMD_ROLE_STATUS_DATA_
{
    int nInstalled;
    int nConfigured;
}PMD_ROLE_STATUS_DATA, *PPMD_ROLE_STATUS_DATA;

//status callback
typedef
uint32_t
(*PFN_ALTER_PROGRESS_CALLBACK)(
    const char *pszTaskUUID,
    const char *pszProgress
    );

//Function pointer defs

//version
typedef uint32_t
(*PFN_PMD_ROLE_VERSION)(
    char **ppszVersion
    );

//open to get a handle for operations.
typedef uint32_t
(*PFN_PMD_ROLE_OPEN)(
    PPMD_ROLE_HANDLE *ppHandle
    );

//close role operations
typedef uint32_t
(*PFN_PMD_ROLE_CLOSE)(
    PPMD_ROLE_HANDLE pHandle
    );

//return installed status, configured status
typedef uint32_t
(*PFN_PMD_ROLE_GET_STATUS)(
    PPMD_ROLE_HANDLE pHandle,
    PPMD_ROLE_STATUS_DATA *ppStatusData
    );

//get list of pre-requisites
typedef uint32_t
(*PFN_PMD_ROLE_GET_PREREQS)(
    PPMD_ROLE_HANDLE pHandle,
    PMD_ROLE_OPERATION nOperation,
    PPMD_ROLE_PREREQ *ppPreReqs,
    uint32_t *pdwPreReqCount
    );

//perform role alter operation
typedef uint32_t
(*PFN_PMD_ROLE_ALTER)(
    PPMD_ROLE_HANDLE pHandle,
    PMD_ROLE_OPERATION nOperation,
    const char *pszConfigJson,
    const char *pszTaskID,
    PFN_ALTER_PROGRESS_CALLBACK pFnCallback,
    PPMD_ROLE_ERROR *ppError
    );

typedef struct _PMD_ROLE_PLUGIN_INTERFACE_
{
    PFN_PMD_ROLE_VERSION      pFnRoleVersion;
    PFN_PMD_ROLE_OPEN         pFnRoleOpen;
    PFN_PMD_ROLE_CLOSE        pFnRoleClose;
    PFN_PMD_ROLE_GET_STATUS   pFnRoleGetStatus;
    PFN_PMD_ROLE_GET_PREREQS  pFnRoleGetPreReqs;
    PFN_PMD_ROLE_ALTER        pFnRoleAlter;
}PMD_ROLE_PLUGIN_INTERFACE, *PPMD_ROLE_PLUGIN_INTERFACE;

//Entry point for plugins
uint32_t
pmd_roleplugin_load_interface(
    PPMD_ROLE_PLUGIN_INTERFACE *ppInterface
    );

//Entry point for plugins
uint32_t
pmd_roleplugin_unload_interface(
    PPMD_ROLE_PLUGIN_INTERFACE pInterface
    );
