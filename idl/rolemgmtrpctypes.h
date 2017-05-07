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


#ifndef __ROLEMGMT_RPC_TYPES_H__
#define __ROLEMGMT_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined NO_LIKEWISE && !defined _WIN32)
#include <lw/types.h>
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <rolemgmtrpctypes.h>")
cpp_quote("#if 0")

#endif

typedef struct _PMD_RPC_ROLEMGMT_ROLE_
{
    wstring_t pwszRole;
}PMD_RPC_ROLEMGMT_ROLE, *PPMD_RPC_ROLEMGMT_ROLE;

typedef struct _PMD_RPC_ROLEMGMT_ROLE_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_ROLEMGMT_ROLE pRoles;
}PMD_RPC_ROLEMGMT_ROLE_ARRAY, *PPMD_RPC_ROLEMGMT_ROLE_ARRAY;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __ROLEMGMT_RPC_TYPES_H__ */
