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

//gpmgmt_api.c
uint32_t
pmd_gpmgmt_get_version(
    char **ppszVersion
    );

uint32_t
pmd_gpmgmt_start_policies(
    );

uint32_t
pmd_gpmgmt_stop_policies(
    );

uint32_t
pmd_gpmgmt_enforce_polices(
    const PPMD_POLICY_DATA pPolicies
    );

void *
pmd_gpmgmt_enforcement_thread(
    void *args
    );

uint32_t
pmd_gpmgmt_execute_polices(
    const PPMD_POLICY_DATA pPolicies,
    const PMD_POLICY_KIND nPolicyKind
    );

uint32_t
pmd_gpmgmt_execute_updatepolicy(
    const PPMD_POLICY_DATA pPolicy
    );

uint32_t
pmd_gpmgmt_update_pkgmgmt_args(
    const PPMD_POLICY_DATA pPolicy,
    PTDNF_CMD_ARGS *ppArgs
    );

uint32_t
pmd_gpmgmt_update_error(
    uint32_t dwErrorCode
    );

uint32_t
pmd_gpmgmt_open_tdnf(
    const PTDNF_CMD_ARGS pArgs,
    PTDNF *ppTdnf
    );

uint32_t
pmd_gpmgmt_invoke_tdnf_alter(
    const PTDNF pTdnf,
    const TDNF_ALTERTYPE nAlterType
    );

uint32_t
pmd_gpmgmt_print_tdnf_args(
    const PTDNF_CMD_ARGS pArgs
    );

uint32_t
pmd_gpmgmt_update_handle_error(
    uint32_t dwErrorCode,
    const PPMD_POLICY_DATA pPolicy
    );