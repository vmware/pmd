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

#define TCP_ENDPOINT     "2016"

#define PROTOCOL_UDP "ncadg_ip_udp"
#define PROTOCOL_TCP "ncacn_ip_tcp"
#define PROTOCOL_NP  "ncacn_np"
#define PROTOCOL_NCALRPC "ncalrpc"

#define DO_RPC(rpc_pfn, sts) \
  do {                       \
    dcethread_exc *exc = NULL;      \
    DCETHREAD_TRY            \
    {                        \
      (sts) = rpc_pfn;       \
    }                        \
    DCETHREAD_CATCH_ALL(exc) \
    {                        \
      sts = dcethread_exc_getstatus(exc); \
    }                        \
    DCETHREAD_ENDTRY         \
  } while (0)

#define PPMD_RPC_PROTECT_LEVEL_NONE        rpc_c_protect_level_none
#define PPMD_RPC_PROTECT_LEVEL_PKT_PRIVACY rpc_c_protect_level_pkt_privacy

#define PPMD_RPC_AUTHN_NONE                rpc_c_authn_none
#define PPMD_RPC_AUTHN_GSS_NEGOTIATE       rpc_c_authn_gss_negotiate

#define PPMD_RPC_AUTHZN_NONE               rpc_c_authz_none
#define PPMD_RPC_AUTHZN_NAME               rpc_c_authz_name


/* Defines related to GSS authentication */

#ifndef GSSAPI_MECH_SPNEGO
/*
 * SPNEGO MECH OID: 1.3.6.1.5.5.2
 * http://www.oid-info.com/get/1.3.6.1.5.5.2
 */
#define GSSAPI_MECH_SPNEGO "\x2b\x06\x01\x05\x05\x02"
#define GSSAPI_MECH_SPNEGO_LEN 6

/*
 * 1.3.6.1.4.1.6876.11711.2.1.1.1
 *
 * {iso(1) identified-organization(3) dod(6) internet(1) private(4)
 *   enterprise(1) 6876 vmwSecurity(11711) vmwAuthentication(2) vmwGSSAPI(1)
 *   vmwSRP(1) vmwSrpCredOptPwd(1)}
 * Official registered GSSAPI_SRP password cred option OID
 */
#ifndef GSSAPI_SRP_CRED_OPT_PW
#define GSSAPI_SRP_CRED_OPT_PW  \
    "\x2b\x06\x01\x04\x01\xb5\x5c\xdb\x3f\x02\x01\x01\x01"
#endif
#ifndef GSSAPI_SRP_CRED_OPT_PW_LEN
#define GSSAPI_SRP_CRED_OPT_PW_LEN  13
#endif

/*
 * 1.3.6.1.4.1.6876.11711.2.1.2.1
 *
 * {iso(1) identified-organization(3) dod(6) internet(1) private(4)
 *   enterprise(1) 6876 vmwSecurity(11711) vmwAuthentication(2) vmwGSSAPI(1)
 *   vmwUNIX(2) vmwSrpCredOptPwd(1)}
 * Official registered GSSAPI_UNIX password cred option OID
 */
#ifndef GSSAPI_UNIX_CRED_OPT_PW
#define GSSAPI_UNIX_CRED_OPT_PW  \
    "\x2b\x06\x01\x04\x01\xb5\x5c\xdb\x3f\x02\x01\x02\x01"
#define GSSAPI_UNIX_CRED_OPT_PW_LEN  13
#endif

#endif
