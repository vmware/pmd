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
gssapi_show_error(
    OM_uint32 maj_status,
    OM_uint32 min_status
    )
{
    OM_uint32 message_context;
    gss_buffer_desc status_string;

    message_context = 0;
    fprintf(stderr, "Maj: %d, Min: %d\n", maj_status, min_status);

    do
    {
        maj_status = gss_display_status(
                         &min_status,
                         maj_status,
                         GSS_C_GSS_CODE,
                         GSS_C_NO_OID,
                         &message_context,
                         &status_string);

        fprintf(stderr, "%.*s\n", \
                (int)status_string.length, \
                (char *)status_string.value);

        gss_release_buffer(&min_status, &status_string);

    } while (message_context != 0);
}


static uint32_t
server_acquire_creds(
    char* service_name,
    gss_OID_desc  *mech,
    gss_cred_id_t *server_creds)
{
    uint32_t dwError = 0;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    gss_name_t server_name = GSS_C_NO_NAME;
    OM_uint32 min = 0;
    OM_uint32 maj = 0;

    gss_OID_desc mech_oid_array[1];
    gss_OID_set_desc desired_mech = {0};


    if (mech)
    {
        desired_mech.count = 1;
        desired_mech.elements = mech_oid_array;
        desired_mech.elements[0] = *mech;
    }

    if (IsNullOrEmptyString(service_name))
    {
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    name_buf.value = service_name;
    name_buf.length = strlen(name_buf.value) + 1;
    maj = gss_import_name(&min, &name_buf,
             GSS_C_NT_HOSTBASED_SERVICE, &server_name);
    if (maj)
    {
        gssapi_show_error(maj, min);
        goto error;
    }
    maj = gss_acquire_cred(&min, server_name, 0,
                   &desired_mech, GSS_C_ACCEPT,
                   server_creds, NULL, NULL);

    if (maj)
    {
        gssapi_show_error(maj, min);
        goto error;
    }

    (void) gss_release_name(&min, &server_name);

cleanup:
    return (DWORD) maj;
error:
    if (maj)
    {
        maj = min ? min : maj;
    }

    if(server_name)
    {
        gss_release_name(&min, &server_name);
    }
    goto cleanup;
}

/*
HTTP/1.1 401 Authorization Required
WWW-Authenticate: Negotiate [token]
Content-Type: text/html
Content-Length: 20
*/

uint32_t
request_negotiate_auth(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse,
    const char* pszToken
    )
{
    uint32_t dwError = 0;
    uint32_t temp = 0;
    const char* pszNegotiate = pszToken ? pszToken : "Negotiate";

    dwError = VmRESTSetHttpStatusVersion(ppResponse, "HTTP/1.1");
    dwError = VmRESTSetHttpStatusCode(ppResponse, "401");
    dwError = VmRESTSetHttpReasonPhrase(ppResponse, "Unauthorized");
    dwError = VmRESTSetHttpHeader(ppResponse, "Connection", "close");
    dwError = VmRESTSetHttpHeader(ppResponse, "Content-Length", "0");
    dwError = VmRESTSetHttpHeader(ppResponse, "WWW-Authenticate", (char *)pszNegotiate);
    dwError = VmRESTSetHttpPayload(pRestHandle, ppResponse,"", 0, &temp );
    dwError = EACCES;
    return dwError;
}

uint32_t
make_negotiate_token(
    gss_buffer_desc *pBuffer,
    char **ppszNegotiate
    )
{
    uint32_t dwError = 0;
    char *pszEncodedData = NULL;
    char *pszNegotiate = NULL;
    int len = 0;

    if (pBuffer)
    {
        dwError = base64_encode(
                      pBuffer->value,
                      pBuffer->length,
                      &pszEncodedData);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError =  PMDAllocateStringPrintf(
                   &pszNegotiate,
                   "Negotiate %s",
                   pszEncodedData ? pszEncodedData : "");
    BAIL_ON_PMD_ERROR(dwError);

    *ppszNegotiate = pszNegotiate;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszEncodedData);
    return dwError;
error:
    PMD_SAFE_FREE_MEMORY(pszNegotiate);
    goto cleanup;
}

uint32_t
verify_krb_auth(
    PVMREST_HANDLE pRestHandle,
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    )
{
    uint32_t dwError = 0;
    char *pszAuthorization = NULL;
    char *pszNegotiate = NULL;
    char *pszDecode = NULL;
    char *pszData = NULL;
    char *pszUser = NULL;
    char *pszToken = NULL;
    OM_uint32 major_status, minor_status;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;
    gss_ctx_id_t gss_context = GSS_C_NO_CONTEXT;
    gss_name_t client_name = GSS_C_NO_NAME;
    static gss_OID_desc gss_spnego_mech_oid_desc =
                                  {6, (void *)"\x2b\x06\x01\x05\x05\x02"};
    static gss_OID gss_spnego_mech_oid = &gss_spnego_mech_oid_desc;
    int nLength = 0;
    gss_cred_id_t server_creds;
    char *pszError = NULL;

    dwError = VmRESTGetHttpHeader(pRequest,
                                  "Authorization",
                                  &pszAuthorization);
    BAIL_ON_PMD_ERROR(dwError);

    if (IsNullOrEmptyString(pszAuthorization))
    {
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszNegotiate = strstr(pszAuthorization, "Negotiate ");
    if (IsNullOrEmptyString(pszAuthorization))
    {
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszData = pszNegotiate + strlen("Negotiate ");

    dwError = base64_decode(pszData, &pszDecode, &nLength);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = server_acquire_creds("HTTP", &gss_spnego_mech_oid_desc, &server_creds);
    BAIL_ON_PMD_ERROR(dwError);

    input_token.length = nLength;
    input_token.value = pszDecode;

    major_status = gss_accept_sec_context(&minor_status,
                               &gss_context,
                               server_creds,
                               &input_token,
                               GSS_C_NO_CHANNEL_BINDINGS,
                               &client_name,
                               &gss_spnego_mech_oid,
                               &output_token,
                               NULL,
                               NULL,
                               NULL);
    if (GSS_ERROR(major_status))
    {
        gssapi_show_error(major_status, minor_status);
        dwError = EACCES;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (output_token.length)
    {
        dwError = make_negotiate_token(&output_token, &pszToken);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (major_status == GSS_S_CONTINUE_NEEDED)
    {
        OM_uint32 min2;
        gss_buffer_desc mech_msg = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc gss_msg = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc minor_msg = GSS_C_EMPTY_BUFFER;
        OM_uint32 msg_ctx = 0;

        gss_oid_to_str(&min2, gss_spnego_mech_oid, &mech_msg);
        gss_display_status(&min2, major_status, GSS_C_GSS_CODE, gss_spnego_mech_oid, &msg_ctx, &gss_msg);
        gss_display_status(&min2, minor_status, GSS_C_MECH_CODE, gss_spnego_mech_oid, &msg_ctx, &minor_msg);

        dwError = PMDAllocateStringPrintf(&pszError,
                      "gss_rc[%d:%*s] mech[%*s] minor[%u:%*s]",
                      major_status, (int)gss_msg.length,
                      (const char *)(gss_msg.value?gss_msg.value:""),
                      (int)mech_msg.length,
                      (const char *)(mech_msg.value?mech_msg.value:""),
                      minor_status, (int)minor_msg.length,
                      (const char *)(minor_msg.value?minor_msg.value:""));

        gss_release_buffer(&min2, &mech_msg);
        gss_release_buffer(&min2, &gss_msg);
        gss_release_buffer(&min2, &minor_msg);
    }
    if (major_status == GSS_S_COMPLETE)
    {
        gss_display_name(&minor_status, client_name, &display_name, NULL);

        dwError = PMDAllocateString(display_name.value, &pszUser);
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    gss_release_buffer(&minor_status, &display_name);
    gss_release_name(&minor_status, &client_name);
    gss_delete_sec_context(&minor_status, &gss_context, GSS_C_NO_BUFFER);
    gss_release_buffer(&minor_status, &output_token);

    PMD_SAFE_FREE_MEMORY(pszDecode);
    PMD_SAFE_FREE_MEMORY(pszError);
    return dwError;
error:
    if(dwError == EACCES)
    {
        request_negotiate_auth(pRestHandle, pRequest, ppResponse, NULL);
    }
    goto cleanup;
}
