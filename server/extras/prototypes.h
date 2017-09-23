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

//rolemgmt_api.c
uint32_t
pmd_rolemgmt_get_version(
    char **ppszVersion
    );

uint32_t
pmd_rolemgmt_get_roles(
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

//security
uint32_t has_admin_access(
    rpc_binding_handle_t h
    );
