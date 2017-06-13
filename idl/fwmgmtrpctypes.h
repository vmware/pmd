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

#ifndef __FIREWALL_RPC_TYPES_H__
#define __FIREWALL_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined NO_LIKEWISE && !defined _WIN32)
#include <lw/types.h>
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <fwmgmtrpctypes.h>")
cpp_quote("#if 0")

#endif

typedef struct _PMD_RPC_FIREWALL_RULE_
{
    wstring_t pwszRule;
}PMD_RPC_FIREWALL_RULE, *PPMD_RPC_FIREWALL_RULE;

typedef struct _PMD_RPC_FIREWALL_RULE_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_FIREWALL_RULE pRules;
}PMD_RPC_FIREWALL_RULE_ARRAY, *PPMD_RPC_FIREWALL_RULE_ARRAY;

typedef struct _PMD_RPC_FIREWALL_CMD_
{
    wstring_t pwszRawCmd;
}PMD_RPC_FIREWALL_CMD, *PPMD_RPC_FIREWALL_CMD;

typedef struct _PMD_RPC_FIREWALL_CMD_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_FIREWALL_CMD pCmds;
}PMD_RPC_FIREWALL_CMD_ARRAY, *PPMD_RPC_FIREWALL_CMD_ARRAY;

typedef struct _PMD_RPC_FIREWALL_TABLE_
{
    wstring_t pwszName;
    PPMD_RPC_FIREWALL_CMD_ARRAY pCmds;
}PMD_RPC_FIREWALL_TABLE, *PPMD_RPC_FIREWALL_TABLE;

typedef struct _PMD_RPC_FIREWALL_TABLE_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_FIREWALL_TABLE pTables;
}PMD_RPC_FIREWALL_TABLE_ARRAY, *PPMD_RPC_FIREWALL_TABLE_ARRAY;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __FIREWALL_RPC_TYPES_H__ */
