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

void
InqAuthInfo(
    handle_t h
    )
{
    char * binding_info;
    error_status_t e;
    rpc_transport_info_handle_t transport_info = NULL;
    unsigned32 rpcstatus = 0;

    unsigned32 uid = 0;
    unsigned32 gid = 0;
    unsigned32 prot_seq = 0;
    struct passwd* pwd;

    rpc_binding_to_string_binding(h, (unsigned char **)&binding_info, &e);
    if (e == rpc_s_ok)
    {
        printf ("OpenHandle called by client: %s\n", binding_info);
    }

    rpc_binding_inq_prot_seq(h, &prot_seq, &rpcstatus);
    printf("prot_seq = %d\n", prot_seq);

    if(prot_seq == rpc_c_protseq_id_ncalrpc)
    {
        rpc_binding_inq_transport_info(h, &transport_info, &rpcstatus);
        printf("Status = %d\n", rpcstatus);

        rpc_lrpc_transport_info_inq_peer_eid(transport_info, &uid, &gid);
        printf("trans = %p, uid = %d, gid = %d\n", transport_info, uid, gid);
    }
    else
    {
        printf("Could not get user info as client is not local\n");
    }
}

unsigned32
pmd_rpc_server_type(
    handle_t hBinding,
    unsigned32* pdwServerType
    )
{
    uint32_t dwError = 0;
    PPMD_CONFIG pConfig = NULL;

    if(!hBinding || !pdwServerType)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_read_config(
                  PMD_CONFIG_FILE_NAME,
                  PMD_CONFIG_MAIN_GROUP,
                  &pConfig);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwServerType = pConfig->nServerType;

cleanup:
    if(pConfig)
    {
        pmd_free_config(pConfig);
    }
    return dwError;

error:
    if(pdwServerType)
    {
        *pdwServerType = 0;
    }
    goto cleanup;
}

unsigned32
pmd_rpc_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    char* pszVersion = NULL;
    wstring_t pwszVersion = NULL;
    
    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszVersion = PACKAGE_VERSION;
    if(IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pwszVersion);
    goto cleanup;
}
