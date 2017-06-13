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
#include "pmd_fwmgmt_types.h"

uint32_t
fwmgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

uint32_t
fwmgmt_get_rules(
    PPMDHANDLE hHandle,
    int nIPV6,
    PPMD_FIREWALL_RULE *ppRules
    );

uint32_t
fwmgmt_add_rule(
    PPMDHANDLE hHandle,
    int nIPV6,
    int nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    );

uint32_t
fwmgmt_delete_rule(
    PPMDHANDLE hHandle,
    int nIPV6,
    int nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    );

uint32_t
fwmgmt_restore(
    PPMDHANDLE hHandle,
    int nIPV6,
    PPMD_FIREWALL_TABLE pTable
    );

void
fwmgmt_free_cmd(
    PPMD_FIREWALL_CMD pCmd
    );

void
fwmgmt_free_table(
    PPMD_FIREWALL_TABLE pTable
    );

void
fwmgmt_free_rules(
    PPMD_FIREWALL_RULE pRules
    );

void
fwmgmt_free_params(
    PPMD_FIREWALL_PARAM pParams
    );
#ifdef __cplusplus
}
#endif
