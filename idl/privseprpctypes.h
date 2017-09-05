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

#ifndef __PRIVSEP_RPC_TYPES_H__
#define __PRIVSEP_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <privseprpctypes.h>")
cpp_quote("#if 0")

#endif

typedef enum
{
    AUTH_MODE_USER_PASS,
    AUTH_MODE_UID,
    AUTH_MODE_KRB
}PRIVSEP_AUTH_MODE;

typedef struct _PRIVSEP_AUTH_T_
{
    wstring_t pwszEncrypted;
    wstring_t pwszContext;
    unsigned32 uid;
    unsigned32 gid;
}PRIVSEP_AUTH_T, *PPRIVSEP_AUTH_T;

typedef struct _PRIVSEP_AUTH_
{
    PRIVSEP_AUTH_MODE nAuthMode;
    PRIVSEP_AUTH_T stAuth;
}PRIVSEP_AUTH, *PPRIVSEP_AUTH;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __PRIVSEP_RPC_TYPES_H__ */
