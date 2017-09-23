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

unsigned32
fwmgmt_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    wstring_t pwszVersion = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(FWMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = fwmgmt_get_version_w(hPMD, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    goto cleanup;
}

unsigned32
fwmgmt_rpc_get_rules(
    handle_t hBinding,
    unsigned32 nIPV6,
    PPMD_RPC_FIREWALL_RULE_ARRAY *ppRpcRuleArray
    )
{
    uint32_t dwError = 0;
    PPMD_RPC_FIREWALL_RULE_ARRAY pRpcRuleArray = NULL;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !ppRpcRuleArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(FWMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = fwmgmt_get_rules_w(hPMD, nIPV6, &pRpcRuleArray);
    BAIL_ON_PMD_ERROR(dwError);

    *ppRpcRuleArray = pRpcRuleArray;

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppRpcRuleArray)
    {
        *ppRpcRuleArray = NULL;
    }
    goto cleanup;
}

unsigned32
fwmgmt_rpc_add_rule(
    handle_t hBinding,
    unsigned32 nIPV6,
    unsigned32 nPersist,
    wstring_t pwszChain,
    wstring_t pwszRuleSpec
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszChain || !pwszRuleSpec)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(FWMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = fwmgmt_add_rule_w(
                  hPMD,
                  nIPV6,
                  nPersist,
                  pwszChain,
                  pwszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    goto cleanup;
}

unsigned32
fwmgmt_rpc_delete_rule(
    handle_t hBinding,
    unsigned32 nIPV6,
    unsigned32 nPersist,
    wstring_t pwszChain,
    wstring_t pwszRuleSpec
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pwszChain || !pwszRuleSpec)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(FWMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = fwmgmt_delete_rule_w(
                  hPMD,
                  nIPV6,
                  nPersist,
                  pwszChain,
                  pwszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    goto cleanup;
}

unsigned32
fwmgmt_rpc_restore(
    handle_t hBinding,
    unsigned32 nIPV6,
    PPMD_RPC_FIREWALL_TABLE_ARRAY pRpcTables
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;

    if(!hBinding || !pRpcTables)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHECK_RPC_ACCESS(hBinding, dwError);

    dwError = rpc_open_privsep_internal(FWMGMT_PRIVSEP, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = fwmgmt_restore_w(hPMD, nIPV6, pRpcTables);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    goto cleanup;
}
