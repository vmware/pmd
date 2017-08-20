/*
 * Copyright © 2017-2018 VMware, Inc.  All Rights Reserved.
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

uint32_t
check_connection_integrity(
    rpc_binding_handle_t hBinding
    )
{
    uint32_t dwError = 0;
    unsigned32 prot_seq = 0;
    rpc_transport_info_handle_t hInfo = NULL;
    gid_t gid;
    uid_t uid;
    idl_char *pszKey = NULL;
    unsigned16 nKeyLen = 0;
    unsigned16 i = 0;
    const char *pszAllowedUser = "pmd";
    struct passwd *pPasswd = NULL;

    if(!hBinding)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPasswd = getpwnam(pszAllowedUser);
    if(!pPasswd)
    {
        dwError = ERROR_PMD_NO_DAEMON_USER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    rpc_binding_inq_prot_seq(hBinding, &prot_seq, &dwError);
    BAIL_ON_PMD_ERROR(dwError);

    if (prot_seq != rpc_c_protseq_id_ncalrpc)
    {
        fprintf(stderr, "server supports local ipc only\n");
        dwError = ERROR_PMD_UNSUPPORTED_PROTOCOL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    rpc_binding_inq_transport_info(hBinding, &hInfo, &dwError);
    BAIL_ON_PMD_ERROR(dwError);

    rpc_lrpc_transport_info_inq_peer_eid(hInfo, &uid, &gid);

    if(uid != pPasswd->pw_uid && gid != pPasswd->pw_gid)
    {
        dwError = ERROR_PMD_INVALID_DAEMON_USER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    if(hInfo)
    {
        rpc_lrpc_transport_info_free(hInfo);
    }
    return dwError;

error:
    goto cleanup;
}
