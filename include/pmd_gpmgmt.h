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


#include <stdint.h>//for uint32_t
#include "pmdtypes.h"
#include "pmd_gpmgmt_types.h"

typedef void* PFN_PMD_GPMGMT_HANDLE; 

//Function pointer defs
   
//version
typedef uint32_t
(*PFN_PMD_POLICY_VERSION)(
    char **ppszVersion
    );
  
//Open policy operations
typedef uint32_t
(*PFN_PMD_POLICY_START)(
    );

//list applicable policies
typedef uint32_t
(*PFN_PMD_POLICY_LIST)(
    PPMD_POLICY_DATA *ppPolicyData
    );

//close policy operations
typedef uint32_t
(*PFN_PMD_POLICY_STOP)(
    );

typedef struct _PMD_POLICY_PLUGIN_INTERFACE_
{   
    PFN_PMD_GPMGMT_HANDLE       hHandle;
    PFN_PMD_POLICY_VERSION      pFnPolicyVersion;
    PFN_PMD_POLICY_START        pFnStartPolicies;
    PFN_PMD_POLICY_LIST         pFnListPolicies;
    PFN_PMD_POLICY_STOP         pFnStopPolicies;
}PMD_POLICY_PLUGIN_INTERFACE, *PPMD_POLICY_PLUGIN_INTERFACE;


//Entry point for group policy plugins
uint32_t
pmd_policy_plugin_load_interface(
    );
 
//Entry point for group policy plugins
uint32_t
pmd_policy_plugin_unload_interface(
    );


//Client defs (client/gpmgmt_api.c)
uint32_t
gpmgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

//gpmgmt.c
uint32_t
gpmgmt_get_policy_kind_enum(
    const char *pPolicyKind,
    PMD_POLICY_KIND *penumKind
    );

uint32_t
gpmgmt_get_policy_type_enum(
    const char *pPolicyType,
    PMD_POLICY_TYPE *penumType
    );

uint32_t
gpmgmt_get_policy_time(
    const char *pPolicyTime,
    time_t *ptmTimeRet
    );

uint32_t
gpmgmt_get_policy_interval(
    const char *pPolicyTime,
    time_t *ptmTimeRet
    );

uint32_t
gpmgmt_get_policy_enabled_enum(
    const char *pPolicyEnable,
    PMD_POLICY_ENABLE *penumEnableRet
    );
   
#ifdef __cplusplus
}
#endif
