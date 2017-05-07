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


#ifndef __NTM_RPC_TYPES_H__
#define __NTM_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined NO_LIKEWISE && !defined _WIN32)
#include <lw/types.h>
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <netmgmtrpctypes.h>")
cpp_quote("#if 0")

#endif

#define NETMGR_RPC_SET_FLAG(v, f) (v) = ((v) | (f))
#define NETMGR_RPC_CLEAR_FLAG(v, f) (v) = ((v) & ~(f))
#define NETMGR_RPC_TEST_FLAG(v, f) (((v) & (f)) != 0)


typedef enum _NET_RPC_LINK_MODE
{
    RPC_LINK_AUTO = 0,
    RPC_LINK_MANUAL,
    RPC_LINK_MODE_UNKNOWN
} NET_RPC_LINK_MODE;

typedef enum _NET_RPC_LINK_STATE
{
    RPC_LINK_DOWN = 0,
    RPC_LINK_UP,
    RPC_LINK_STATE_UNKNOWN
} NET_RPC_LINK_STATE;

typedef struct _NET_RPC_LINK_INFO
{
    wstring_t pwszInterfaceName;
    wstring_t pwszMacAddress;
    unsigned32 mtu;
    NET_RPC_LINK_MODE mode;
    NET_RPC_LINK_STATE state;
} NET_RPC_LINK_INFO, *PNET_RPC_LINK_INFO;

typedef struct _NET_RPC_LINK_INFO_ARRAY
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PNET_RPC_LINK_INFO pRpcLinkInfo;
} NET_RPC_LINK_INFO_ARRAY, *PNET_RPC_LINK_INFO_ARRAY;


typedef enum _NET_RPC_IPV4_ADDR_MODE
{
    RPC_IPV4_ADDR_MODE_NONE = 0,
    RPC_IPV4_ADDR_MODE_STATIC,
    RPC_IPV4_ADDR_MODE_DHCP,
    RPC_IPV4_ADDR_MODE_MAX
} NET_RPC_IPV4_ADDR_MODE;

typedef enum _NET_RPC_ADDR_TYPE
{
    RPC_STATIC_IPV4        =  0x00000001,
    RPC_STATIC_IPV6        =  0x00000002,
    RPC_DHCP_IPV4          =  0x00000010,
    RPC_DHCP_IPV6          =  0x00000020,
    RPC_AUTO_IPV6          =  0x00000040,
    RPC_LINK_LOCAL_IPV6    =  0x00000080
} NET_RPC_ADDR_TYPE;

typedef struct _NET_RPC_IP_ADDR
{
    wstring_t pwszInterfaceName;
    NET_RPC_ADDR_TYPE type;
    wstring_t pwszIPAddrPrefix;
} NET_RPC_IP_ADDR, *PNET_RPC_IP_ADDR;

typedef struct _NET_RPC_IP_ADDR_ARRAY
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PNET_RPC_IP_ADDR pRpcIpAddr;
} NET_RPC_IP_ADDR_ARRAY, *PNET_RPC_IP_ADDR_ARRAY;


typedef enum _NET_RPC_ROUTE_SCOPE
{
    RPC_GLOBAL_ROUTE = 0,
    RPC_LINK_ROUTE,
    RPC_HOST_ROUTE,
    RPC_ROUTE_SCOPE_MAX
} NET_RPC_ROUTE_SCOPE;

typedef struct _NET_RPC_IP_ROUTE
{
    wstring_t pwszInterfaceName;
    wstring_t pwszDestNetwork;
    wstring_t pwszSourceNetwork;
    wstring_t pwszGateway;
    NET_RPC_ROUTE_SCOPE scope;
    unsigned32 dwMetric;
    unsigned32 dwTableId;
} NET_RPC_IP_ROUTE, *PNET_RPC_IP_ROUTE;

typedef struct _NET_RPC_IP_ROUTE_ARRAY
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PNET_RPC_IP_ROUTE pRpcIpRoute;
} NET_RPC_IP_ROUTE_ARRAY, *PNET_RPC_IP_ROUTE_ARRAY;


typedef enum _NET_RPC_DNS_MODE
{
    RPC_DNS_MODE_INVALID = 0,
    RPC_STATIC_DNS,
    RPC_DHCP_DNS,
    RPC_DNS_MODE_MAX
} NET_RPC_DNS_MODE;

typedef enum _NET_RPC_FW_RULE_TYPE
{
    RPC_FW_RAW = 0,
    RPC_FW_POLICY,
    RPC_FW_RULE_TYPE_MAX
} NET_RPC_FW_RULE_TYPE;

typedef struct _NET_RPC_FW_RULE
{
    unsigned8 ipVersion;
    wstring_t pwszRawFwRule;     // e.g. -A INPUT  -i lo -j ACCEPT
} NET_RPC_FW_RULE, *PNET_RPC_FW_RULE;

typedef struct _NET_RPC_FW_RULE_ARRAY
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PNET_RPC_FW_RULE pRpcNetFwRule;
} NET_RPC_FW_RULE_ARRAY, *PNET_RPC_FW_RULE_ARRAY;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __NTM_RPC_TYPES_H__ */
