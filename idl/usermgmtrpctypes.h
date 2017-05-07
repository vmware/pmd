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


#ifndef __USERMGMT_RPC_TYPES_H__
#define __USERMGMT_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined NO_LIKEWISE && !defined _WIN32)
#include <lw/types.h>
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <usermgmtrpctypes.h>")
cpp_quote("#if 0")

#endif

typedef struct _PMD_RPC_USER_
{
    unsigned32 nUID;
    unsigned32 nGID;
    wstring_t pwszName;
    wstring_t pwszRealName;
    wstring_t pwszHomeDir;
    wstring_t pwszShell;
}PMD_RPC_USER, *PPMD_RPC_USER;

typedef struct _PMD_RPC_USER_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_USER pUsers;
}PMD_RPC_USER_ARRAY, *PPMD_RPC_USER_ARRAY;

typedef struct _PMD_RPC_GROUP_
{
    unsigned32 nGID;
    wstring_t pwszName;
    PPMD_WSTRING_ARRAY pMembers;
}PMD_RPC_GROUP, *PPMD_RPC_GROUP;

typedef struct _PMD_RPC_GROUP_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_GROUP pGroups;
}PMD_RPC_GROUP_ARRAY, *PPMD_RPC_GROUP_ARRAY;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __USERMGMT_RPC_TYPES_H__ */
