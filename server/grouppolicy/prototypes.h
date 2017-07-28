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

uint32_t
pmd_gpmgmt_load_policies(
    PPMD_POLICY_DATA *ppPolicies
    );

uint32_t
pmd_gpmgmt_print_polices(
    PPMD_POLICY_DATA pPolicies
    );
    
uint32_t
pmd_gpmgmt_load_each_policy(
    const char *pszPolicyName,
    json_t *pPolicyData,
    PPMD_POLICY_DATA *ppPolicy
    );

uint32_t
pmd_gpmgmt_create_policy_json(
        );

void
gpmgmt_free_policies(
    PPMD_POLICY_DATA pPolicies
    );