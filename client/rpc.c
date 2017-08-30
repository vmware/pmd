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
chk_dce_err(
    error_status_t ecode,
    char* where,
    char* why,
    unsigned int fatal
    )
{
    dce_error_string_t errstr;
    int error_status;

    if (ecode != error_status_ok)
    {
        dce_error_inq_text(ecode, (unsigned char *) errstr, &error_status);
        if (error_status == error_status_ok)
            printf("ERROR.  where = <%s> why = <%s> error code = 0x%x"
                   "reason = <%s>\n",
                   where, why, ecode, errstr);
        else
            printf("ERROR.  where = <%s> why = <%s> error code = 0x%x\n",
                   where, why, ecode);

        if (fatal) exit(1);
    }
}

static
uint32_t
create_auth_identity(
    const char *pszUser,
    const char *pszDomain,
    const char *pszPassword,
    char **ppszUPN,
    rpc_auth_identity_handle_t *pAuthHandle)
{
    OM_uint32 dwError = 0;
    OM_uint32 dwMin = 0;
    const gss_OID_desc gss_srp_password_oid =
        {GSSAPI_SRP_CRED_OPT_PW_LEN, (void *) GSSAPI_SRP_CRED_OPT_PW};
    const gss_OID_desc gss_unix_password_oid =
        {GSSAPI_UNIX_CRED_OPT_PW_LEN, (void *) GSSAPI_UNIX_CRED_OPT_PW};
    const gss_OID_desc spnego_mech_oid =
        {GSSAPI_MECH_SPNEGO_LEN, (void *) GSSAPI_MECH_SPNEGO};
    gss_OID pSelectedOID = NULL;
    gss_buffer_desc stNameBuff = {0};
    gss_buffer_desc stPasswordBuff = {0};
    gss_name_t gss_name_buf = NULL;
    size_t nUPNLength = 0;
    char *pszUPN = NULL;
    gss_cred_id_t cred_handle = NULL;
    gss_OID_desc mech_oid_array[1];
    gss_OID_set_desc desired_mech = {0};
    const char chSep = '@';

    if(IsNullOrEmptyString(pszUser) ||
       IsNullOrEmptyString(pszPassword) ||
       !ppszUPN ||
       !pAuthHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(
                  &pszUPN,
                  "%s%s%s",
                  pszUser,
                  IsNullOrEmptyString(pszDomain) ? "" : "@",
                  IsNullOrEmptyString(pszDomain) ? "" : pszDomain);
    BAIL_ON_PMD_ERROR(dwError);

    stNameBuff.value = pszUPN;
    stNameBuff.length = strlen(pszUPN);
    dwError = gss_import_name(
              &dwMin,
              &stNameBuff,
              GSS_C_NT_USER_NAME,
              &gss_name_buf);
    BAIL_ON_PMD_ERROR(dwError);

    /*
     * Use SPNEGO mech OID to acquire cred
     */
    desired_mech.count = 1;
    desired_mech.elements = mech_oid_array;
    desired_mech.elements[0] = spnego_mech_oid;
    dwError = gss_acquire_cred(
              &dwMin,
              gss_name_buf,
              0,
              &desired_mech,
              GSS_C_INITIATE,
              &cred_handle,
              NULL,
              NULL);
    BAIL_ON_PMD_ERROR(dwError);

    stPasswordBuff.value = (char *)pszPassword;
    stPasswordBuff.length = strlen(stPasswordBuff.value);
    pSelectedOID = strchr(pszUPN, chSep) ?
                       (gss_OID)&gss_srp_password_oid :
                       (gss_OID)&gss_unix_password_oid;
    dwError = gss_set_cred_option(
              &dwMin,
              &cred_handle,
              pSelectedOID,
              &stPasswordBuff);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszUPN = pszUPN;
    *pAuthHandle = (rpc_auth_identity_handle_t) cred_handle;

cleanup:
    return dwError;

error:
    dwError = dwMin ? dwMin : dwError;

    PMD_SAFE_FREE_MEMORY(pszUPN);
    if (gss_name_buf)
    {
        gss_release_name(&dwMin, &gss_name_buf);
    }
    goto cleanup;
}

uint32_t
get_client_rpc_binding(
    rpc_binding_handle_t* binding_handle,
    rpc_if_handle_t interface_spec,
    const char* hostname,
    const char* username,
    const char* domain,
    const char* password,
    const char* protocol,
    const char* endpoint,
    const char* spn
    )
{
    uint32_t dwError = 0;
    char* string_binding = NULL;
    error_status_t status;
    unsigned char* pszUPN = NULL;
    rpc_auth_identity_handle_t rpc_identity_h = NULL;

    /*
     * create a string binding given the command line parameters and
     * resolve it into a full binding handle using the endpoint mapper.
     *  The binding handle resolution is handled by the runtime library
     */

    rpc_string_binding_compose(NULL,
			       (unsigned char *) protocol,
			       (unsigned char *) hostname,
			       (unsigned char *) endpoint,
			       NULL,
			       (unsigned char **) &string_binding,
			       &status);
    chk_dce_err(status,
                "rpc_string_binding_compose()",
                "get_client_rpc_binding", 1);

    rpc_binding_from_string_binding((unsigned char *)string_binding,
                                    binding_handle,
                                    &status);
    chk_dce_err(status,
                "rpc_binding_from_string_binding()",
                "get_client_rpc_binding", 1);

    rpc_string_free((unsigned char **) &string_binding, &status);
    chk_dce_err(status, "rpc_string_free()", "get_client_rpc_binding", 1);

    if(strcmp(protocol, PROTOCOL_NCALRPC) != 0)
    {
        if(IsNullOrEmptyString(username) ||
           IsNullOrEmptyString(password))
        {
            if(IsNullOrEmptyString(spn))
            {
                dwError = ERROR_PMD_ACCESS_DENIED;
                BAIL_ON_PMD_ERROR(dwError);
            }
            rpc_binding_set_auth_info(
                    *binding_handle,
                    (unsigned char *)spn,
                    0,
                    PPMD_RPC_AUTHN_GSS_NEGOTIATE,
                    rpc_identity_h,
                    PPMD_RPC_AUTHZN_NAME,
                    &dwError);
            BAIL_ON_PMD_ERROR(dwError);
        }

        else
        {
            dwError = create_auth_identity(
                      username,
                      domain,
                      password,
                      (char**)&pszUPN,
                      &rpc_identity_h);
            BAIL_ON_PMD_ERROR(dwError);

            rpc_binding_set_auth_info(
                    *binding_handle,
                    pszUPN,
                    PPMD_RPC_PROTECT_LEVEL_PKT_PRIVACY,
                    PPMD_RPC_AUTHN_GSS_NEGOTIATE,
                    rpc_identity_h,
                    PPMD_RPC_AUTHZN_NAME,
                    &dwError);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
    /*
     * Get a printable rendition of the binding handle and echo to
     * the user.
     */

    rpc_binding_to_string_binding(*binding_handle,
                                  (unsigned char **)&string_binding,
                                  &status);
    chk_dce_err(status,
                "rpc_binding_to_string_binding()",
                "get_client_rpc_binding", 1);

    rpc_string_free((unsigned char **) &string_binding, &status);
    chk_dce_err(status, "rpc_string_free()", "get_client_rpc_binding", 1);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
rpc_open(
    const char* pszModule,
    const char* pszServer,
    const char* pszUser,
    const char* pszDomain,
    const char* pszPass,
    const char* pszSpn,
    PPMDHANDLE* phHandle
    )
{
    uint32_t dwError = 0;
    PMDHANDLE* hHandle = NULL;
    char* pszProt = PROTOCOL_TCP;
    char* pszEndpoint = PMD_RPC_TCP_END_POINT;
    int nIndex = 0;

    struct _stKnownIfspec
    {
        const char* pszModule;
        rpc_if_handle_t interface_spec;
    }knownIfspecs[] =
    {
#ifdef DEMO_ENABLED
        {"demo", demo_v1_0_c_ifspec},
        {"demo_privsep", demo_privsep_v1_0_c_ifspec},
#endif
        {"fwmgmt", fwmgmt_v1_0_c_ifspec},
        {"pkg", pkg_v1_0_c_ifspec},
        {"pmd", pmd_v1_0_c_ifspec},
        {"net", netmgmt_v1_0_c_ifspec},
        {"rpmostree", rpmostree_v1_0_c_ifspec},
        {"usermgmt", usermgmt_v1_0_c_ifspec},
    };

    int nNumKnownIfspecs =
        sizeof(knownIfspecs)/sizeof(knownIfspecs[0]);

    rpc_if_handle_t spec = NULL;
    for(nIndex = 0; nIndex < nNumKnownIfspecs; ++nIndex)
    {
        if(!strcasecmp(knownIfspecs[nIndex].pszModule, pszModule))
        {
            spec = knownIfspecs[nIndex].interface_spec;
            break;
        }
    }

    if(!spec)
    {
        fprintf(stderr, "Module %s is not registered\n", pszModule);
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pszServer || !strcasecmp(pszServer, "localhost"))
    {
        pszProt = PROTOCOL_NCALRPC;
        pszEndpoint = PMD_NCALRPC_END_POINT;
    }

    if(!IsNullOrEmptyString(pszServer) &&
       !strcasecmp(pszServer, PMD_PRIVSEP_NCALRPC_END_POINT))
    {
        pszProt = PROTOCOL_NCALRPC;
        pszEndpoint = PMD_PRIVSEP_NCALRPC_END_POINT;
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMDHANDLE),
                  (void**)&hHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_client_rpc_binding(
              &hHandle->hRpc,
              spec,
              pszServer,
              pszUser,
              pszDomain,
              pszPass,
              pszProt,
              pszEndpoint,
              pszSpn);
    BAIL_ON_PMD_ERROR(dwError);

    *phHandle = hHandle;

cleanup:
    return dwError;
error:
    if(phHandle)
    {
        *phHandle = NULL;
    }
    PMDFreeMemory(hHandle);
    goto cleanup;
}

uint32_t
rpc_open_privsep(
    const char *pszModule,
    PPMDHANDLE* phHandle
    )
{
    uint32_t dwError = 0;
    int nIndex = 0;
    PPMDHANDLE hHandle = NULL;

    struct _stKnownIfspec
    {
        const char* pszModule;
        rpc_if_handle_t interface_spec;
    }knownIfspecs[] =
    {
#ifdef DEMO_ENABLED
        {"demo_privsep", demo_privsep_v1_0_c_ifspec},
#endif
    };

    int nNumKnownIfspecs =
        sizeof(knownIfspecs)/sizeof(knownIfspecs[0]);

    rpc_if_handle_t spec = NULL;

    if(IsNullOrEmptyString(pszModule) || !phHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(nIndex = 0; nIndex < nNumKnownIfspecs; ++nIndex)
    {
        if(!strcasecmp(knownIfspecs[nIndex].pszModule, pszModule))
        {
            spec = knownIfspecs[nIndex].interface_spec;
            break;
        }
    }

    if(!spec)
    {
        fprintf(stderr, "Module %s is not registered\n", pszModule);
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(
                  sizeof(PMDHANDLE),
                  (void**)&hHandle);
    BAIL_ON_PMD_ERROR(dwError);
    hHandle->nPrivSep = 1;

    dwError = get_client_rpc_binding(
              &hHandle->hRpc,
              spec,
              NULL,
              NULL,
              NULL,
              NULL,
              PROTOCOL_NCALRPC,
              PMD_PRIVSEP_NCALRPC_END_POINT,
              NULL);
    BAIL_ON_PMD_ERROR(dwError);

    *phHandle = hHandle;
cleanup:
    return dwError;
error:
    if(phHandle)
    {
        *phHandle = NULL;
    }
    rpc_free_handle(hHandle);
    goto cleanup;
}

void
rpc_free_handle(
    PPMDHANDLE hPMD
    )
{
    if(!hPMD)
    {
        return;
    }
    if(hPMD->hRpc)
    {
        PMDRpcFreeBinding(&hPMD->hRpc);
    }
    PMDFreeMemory(hPMD);
}
