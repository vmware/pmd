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


#ifndef __RPMOSTREE_RPC_TYPES_H__
#define __RPMOSTREE_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined NO_LIKEWISE && !defined _WIN32)
#include <lw/types.h>
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <rpmostreerpctypes.h>")
cpp_quote("#if 0")

#endif

typedef struct _PMD_RPMOSTREE_SERVER_INFO_
{
    unsigned32 dwServerType;
    wstring_t pwszServerUrl;
    wstring_t pwszCurrentHash;
}PMD_RPMOSTREE_SERVER_INFO, *PPMD_RPMOSTREE_SERVER_INFO;

typedef struct _PMD_RPMOSTREE_CLIENT_INFO_
{
    unsigned32 dwServerType;
    wstring_t pwszComposeServer;
    wstring_t pwszCurrentHash;
    wstring_t pwszLastSyncDate;
}PMD_RPMOSTREE_CLIENT_INFO, *PPMD_RPMOSTREE_CLIENT_INFO;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __RPMOSTREE_RPC_TYPES_H__ */
