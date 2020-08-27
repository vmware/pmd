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


#ifndef __PMDTYPES_H__
#define __PMDTYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#define PMD_NCALRPC_BASE              "/var/run/pmd"
#define PMD_NCALRPC_SOCKET            "pmd_socket"
#define PMD_NCALRPC_END_POINT         PMD_NCALRPC_BASE"/"PMD_NCALRPC_SOCKET
#define PMD_PRIVSEP_NCALRPC_BASE      "/var/run/pmdprivsepd"
#define PMD_PRIVSEP_NCALRPC_SOCKET    "pmd_privsepd_socket"
#define PMD_PRIVSEP_NCALRPC_END_POINT PMD_PRIVSEP_NCALRPC_BASE"/"PMD_PRIVSEP_NCALRPC_SOCKET
#define PMD_END_POINT                 "pmdserver"
#define PMD_SEPARATOR                 "/"
#define PMD_RPC_TCP_END_POINT         "2016"

#ifdef _DCE_IDL_

cpp_quote("#include <pmdrpctypes.h>")
cpp_quote("#if 0")

#endif

#ifndef PMD_WSTRING_DEFINED
#define PMD_WSTRING_DEFINED 1
typedef
#ifdef _DCE_IDL_
[ptr, string]
#endif
unsigned short* wstring_t;   /* wchar16_t */
#endif /* PMD_WSTRING_DEFINED */

#ifndef PMD_WSTRING_ARRAY_DEFINED
#define PMD_WSTRING_ARRAY_DEFINED 1
typedef struct _PMD_WSTRING_ARRAY
{
unsigned32 dwCount;
#ifdef _DCE_IDL_
[size_is(dwCount)]
#endif
wstring_t *ppwszStrings;
}PMD_WSTRING_ARRAY, *PPMD_WSTRING_ARRAY;
#endif /* PMD_WSTRING_ARRAY_DEFINED */

#ifndef PMD_INT_ARRAY_DEFINED
#define PMD_INT_ARRAY_DEFINED 1
typedef struct _INT_ARRAY
{
unsigned32 dwCount;
#ifdef _DCE_IDL_
[size_is(dwCount)]
#endif
signed32 *pnInts;
}INT_ARRAY, *PINT_ARRAY;
#endif /* PMD_INT_ARRAY_DEFINED */


#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __PMDTYPES_H__ */
