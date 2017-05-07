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
#include "pmd_rolemgmt_types.h"

uint32_t
rolemgmt_get_version(
    PPMDHANDLE hHandle,
    char **ppszVersion
    );

uint32_t
rolemgmt_get_roles(
    PPMDHANDLE hHandle,
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

void
rolemgmt_free_roles(
    PPMD_ROLEMGMT_ROLE pRoles
    );

#ifdef __cplusplus
}
#endif
