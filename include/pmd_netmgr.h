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
#include "pmderror.h"

uint32_t
netmgr_client_set_mac_addr(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    const char *pszMacAddress
);

uint32_t
netmgr_client_get_mac_addr(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    char **ppszMacAddress
);

uint32_t
netmgr_client_set_link_mode(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_MODE linkMode
);

uint32_t
netmgr_client_get_link_mode(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_MODE *pLinkMode
);

uint32_t
netmgr_client_set_link_mtu(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    uint32_t mtu
);

uint32_t
netmgr_client_get_link_mtu(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    uint32_t *pMtu
);

uint32_t
netmgr_client_set_link_state(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_STATE linkState
);

uint32_t
netmgr_client_get_link_state(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_STATE *pLinkState
);

uint32_t
netmgr_client_ifup(
    PPMDHANDLE hHandle,
    const char *pszIfname
);

uint32_t
netmgr_client_ifdown(
    PPMDHANDLE hHandle,
    const char *pszIfname
);

uint32_t
netmgr_client_get_link_info(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_INFO **ppLinkInfo
);

uint32_t
netmgr_client_set_ipv4_addr_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_IPV4_ADDR_MODE mode,
    char *pszIPv4AddrPrefix,
    char *pszIPv4Gateway
    );

uint32_t
netmgr_client_get_ipv4_addr_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_IPV4_ADDR_MODE *pMode,
    char **ppszIPv4AddrPrefix,
    char **ppszIPv4Gateway
    );

uint32_t
netmgr_client_add_static_ipv6_addr(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszIPv6AddrPrefix
    );

uint32_t
netmgr_client_delete_static_ipv6_addr(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszIPv6AddrPrefix
    );

uint32_t
netmgr_client_set_ipv6_addr_mode(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
    );

uint32_t
netmgr_client_get_ipv6_addr_mode(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
    );

uint32_t
netmgr_client_set_ipv6_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszIPv6Gateway
    );

uint32_t
netmgr_client_get_ipv6_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char **ppszIPv6Gateway
    );

uint32_t
netmgr_client_get_ip_addr(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t addrTypes,
    size_t *pCount,
    NET_IP_ADDR ***pppIpAddrList
    );

uint32_t
netmgr_client_add_static_ip_route(
    PPMDHANDLE hHandle,
    NET_IP_ROUTE *pRoute
);

uint32_t
netmgr_client_delete_static_ip_route(
    PPMDHANDLE hHandle,
    NET_IP_ROUTE *pRoute
);

uint32_t
netmgr_client_get_static_ip_routes(
    PPMDHANDLE hHandle,
    char *pszIfname,
    size_t *pCount,
    NET_IP_ROUTE ***pppRouteList
);

uint32_t
netmgr_client_set_dns_servers(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_DNS_MODE mode,
    size_t count,
    char **ppszDnsServers
    );

uint32_t
netmgr_client_get_dns_servers(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***pppszDnsServers
    );

uint32_t
netmgr_client_set_dns_domains(
    PPMDHANDLE hHandle,
    char *pszIfname,
    size_t count,
    char **ppszDnsDomains
    );

uint32_t
netmgr_client_get_dns_domains(
    PPMDHANDLE hHandle,
    char *pszIfname,
    size_t *pCount,
    char ***pppszDnsDomains
    );

uint32_t
netmgr_client_get_iaid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t *pdwIaid
    );

uint32_t
netmgr_client_set_iaid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t dwIaid
    );

uint32_t
netmgr_client_get_duid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char **ppszDuid
    );

uint32_t
netmgr_client_set_duid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszDuid
    );

//ntpd related
uint32_t
netmgr_client_set_ntp_servers(
    PPMDHANDLE hHandle,
    size_t nCount,
    char **ppszNtpServers);

uint32_t
netmgr_client_add_ntp_servers(
    PPMDHANDLE hHandle,
    size_t nCount,
    const char **ppszNtpServers);

uint32_t
netmgr_client_delete_ntp_servers(
    PPMDHANDLE hHandle,
    size_t nCount,
    const char **ppszNtpServers);

uint32_t
netmgr_client_get_ntp_servers(
    PPMDHANDLE hHandle,
    size_t *pnCount,
    char ***pppszNtpServers);

uint32_t
netmgr_client_set_hostname(
    PPMDHANDLE hHandle,
    const char *pszHostname);

uint32_t
netmgr_client_get_hostname(
    PPMDHANDLE hHandle,
    char **ppszHostname);

uint32_t
netmgr_client_wait_for_link_up(
    PPMDHANDLE hHandle,
    const char *pszInterfaceName,
    uint32_t dwTimeout);

uint32_t
netmgr_client_wait_for_ip(
    PPMDHANDLE hHandle,
    const char *pszInterfaceName,
    uint32_t dwTimeout,
    NET_ADDR_TYPE dwAddrTypes);

uint32_t
netmgr_client_get_error_info(
    PPMDHANDLE hHandle,
    uint32_t nmErrCode,
    char **ppszErrInfo);

uint32_t
netmgr_client_set_network_param(
    PPMDHANDLE hHandle,
    const char *pszObjectName,
    const char *pszParamName,
    const char *pszParamValue);

uint32_t
netmgr_client_get_network_param(
    PPMDHANDLE hHandle,
    const char *pszObjectName,
    const char *pszParamName,
    char **ppszParamValue);

#ifdef __cplusplus
}
#endif
