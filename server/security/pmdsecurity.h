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
init_security_config(
    const char *pszApiSecurityConf,
    PPMD_SECURITY_CONTEXT *ppContext
    );

uint32_t
save_security_config(
    const char *pszApiSecurityConf,
    PPMD_SECURITY_CONTEXT *ppContext
    );

void
free_security_context(
    PPMD_SECURITY_CONTEXT pContext
    );
// authz.c
uint32_t has_admin_access(
    rpc_binding_handle_t h
    );

uint32_t
has_api_access(
    rpc_binding_handle_t hBinding,
    const char *pszApiName
    );
