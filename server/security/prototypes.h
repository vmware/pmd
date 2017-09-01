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
//apisecurity.c
uint32_t
init_module_security(
    PCONF_DATA pData,
    PPMD_MODULE_SECURITY *ppModuleSecurity
    );

uint32_t
check_access_uid_gid(
    PPMD_SECURITY_CONTEXT pContext,
    uid_t uid,
    gid_t gid,
    const char *psModuleName,
    const char *pszApiName
    );

void
free_api_security(
    PPMD_API_SECURITY pApiSecurity
    );

void
free_module_security(
    PPMD_MODULE_SECURITY pModuleSecurity
    );

// authz.c
uint32_t
pmd_check_password(
    const char* user_name,
    const char* password,
    uint32_t* valid
    );

uint32_t has_admin_access(
    rpc_binding_handle_t h
    );

uint32_t
has_group_access(
    rpc_binding_handle_t hBinding,
    const char* domain_group,
    const char* local_group
    );

uint32_t
rsa_public_encrypt(
    const char *pszData,
    const char *pszPubKeyFile,
    unsigned char **ppszEncrypted,
    int *pnEncryptedLength
    );

uint32_t
rsa_private_decrypt(
    unsigned char *pszEncrypted,
    int nEncryptedLength,
    const char *pszPrivateKeyFile,
    unsigned char **ppszDecrypted
    );
//privsep
uint32_t
rpc_open_privsep(
    const char *pszModule,
    PPMDHANDLE* phHandle
    );

uint32_t
privsepd_client_basic_auth(
    PPMDHANDLE hHandle,
    const char *pszBasicAuth,
    const char *pszContext,
    unsigned32 *pnValid
    );
//utils
uint32_t
base64_encode(
    const unsigned char* pszInput,
    const size_t nInputLength,
    char** ppszOutput
    );

uint32_t
base64_decode(
    const char* pszInput,
    char** ppszOutput,
    int *pnLength
    );
