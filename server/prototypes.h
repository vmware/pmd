/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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
//netmgmtrestapi.c
uint32_t
net_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

uint32_t
net_rest_add_dns_domain(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_dns_domain(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_dns_domains(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_dns_domains(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_add_dns_server(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_dns_server(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_dns_servers(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_dns_servers(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_dhcp_duid(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_dhcp_duid(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_dhcp_iaid(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_dhcp_iaid(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_ifdown(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_ifup(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_ip_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_static_ip_route(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_static_ip_route(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_static_ip_route(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_ipv4_gateway(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_ipv4_gateway(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_ipv6_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_ipv6_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_static_ipv6_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_static_ipv6_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_ipv6_gateway(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_ipv6_gateway(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_ipv6_addr_mode(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_ipv6_addr_mode(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_link_info(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_link_mode(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_link_mode(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_link_mtu(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_link_mtu(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_link_state(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_link_state(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_mac_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_mac_addr(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_ntp_servers(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_ntp_servers(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_ntp_servers(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_hostname(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_set_hostname(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_waitforlink(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_waitforip(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_get_version(
    void *pInputJson,
    void **ppOutputJson
    );

//fwmgmt_privsep
uint32_t
fwmgmt_get_version_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszVersion
    );

uint32_t
fwmgmt_get_rules_w(
    PPMDHANDLE hHandle,
    int nIPV6,
    PPMD_RPC_FIREWALL_RULE_ARRAY *ppRuleArray
    );

uint32_t
fwmgmt_add_rule_w(
    PPMDHANDLE hHandle,
    int nIPV6,
    int nPersist,
    const wstring_t pwszChain,
    const wstring_t pwszRuleSpec
    );

uint32_t
fwmgmt_delete_rule_w(
    PPMDHANDLE hHandle,
    int nIPV6,
    int nPersist,
    const wstring_t pwszChain,
    const wstring_t pwszRuleSpec
    );

uint32_t
fwmgmt_restore_w(
    PPMDHANDLE hHandle,
    int nIPV6,
    PPMD_RPC_FIREWALL_TABLE_ARRAY pRpcTables
    );
//netmgmt privsep
uint32_t
netmgr_client_get_hostname_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszHostname
);

uint32_t
netmgr_client_set_mac_addr_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszMacAddress
);

uint32_t
netmgr_client_get_mac_addr_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    wstring_t *ppwszMacAddress
);

uint32_t
netmgr_client_set_link_mode_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_RPC_LINK_MODE rpcLinkMode
    );

uint32_t
netmgr_client_get_link_mode_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_RPC_LINK_MODE *pLinkMode
);

uint32_t
netmgr_client_get_network_param_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszObjectName,
    const wstring_t pwszParamName,
    wstring_t *ppwszParamValue
    );

uint32_t
netmgr_client_set_network_param_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszObjectName,
    const wstring_t pwszParamName,
    const wstring_t pwszParamValue
    );

uint32_t
netmgr_client_set_link_mtu_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t mtu
    );

uint32_t
netmgr_client_get_link_mtu_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t *pnMTU
    );

uint32_t
netmgr_client_set_link_state_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_LINK_STATE linkState
    );

uint32_t
netmgr_client_get_link_state_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_RPC_LINK_STATE *prpcLinkState
    );

uint32_t
netmgr_client_ifup_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname
    );

uint32_t
netmgr_client_ifdown_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname
    );

uint32_t
netmgr_client_get_link_info_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    PNET_RPC_LINK_INFO_ARRAY *ppLinkInfoArray
    );

uint32_t
netmgr_client_set_ipv4_addr_gateway_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_IPV4_ADDR_MODE mode,
    wstring_t pwszIPv4AddrPrefix,
    wstring_t pwszIPv4Gateway
    );

uint32_t
netmgr_client_get_ipv4_addr_gateway_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_RPC_IPV4_ADDR_MODE *pMode,
    wstring_t *ppwszIPv4AddrPrefix,
    wstring_t *ppwszIPv4Gateway
    );

uint32_t
netmgr_client_add_static_ipv6_addr_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    const wstring_t pwszIPv6AddrPrefix
    );

uint32_t
netmgr_client_delete_static_ipv6_addr_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszIPv6AddrPrefix
    );

uint32_t
netmgr_client_set_ipv6_addr_mode_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
    );

uint32_t
netmgr_client_get_ipv6_addr_mode_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
    );

uint32_t
netmgr_client_set_ipv6_gateway_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    const wstring_t pwszIPv6Gateway
    );

uint32_t
netmgr_client_get_ipv6_gateway_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    wstring_t *ppwszIPv6Gateway
    );

uint32_t
netmgr_client_get_ip_addr_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t addrTypes,
    NET_RPC_IP_ADDR_ARRAY **ppIpAddrArray
    );

uint32_t
netmgr_client_add_static_ip_route_w(
    PPMDHANDLE hHandle,
    NET_RPC_IP_ROUTE *pIpRoute
    );

uint32_t
netmgr_client_delete_static_ip_route_w(
    PPMDHANDLE hHandle,
    NET_RPC_IP_ROUTE *pIpRoute
    );

uint32_t
netmgr_client_get_static_ip_routes_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    PNET_RPC_IP_ROUTE_ARRAY *ppIpRouteArray
    );

uint32_t
netmgr_client_add_dns_server_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsServer
    );

uint32_t
netmgr_client_delete_dns_server_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsServer
    );

uint32_t
netmgr_client_set_dns_servers_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_DNS_MODE mode,
    PPMD_WSTRING_ARRAY pwszDnsServers
    );

uint32_t
netmgr_client_get_dns_servers_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_RPC_DNS_MODE *pMode,
    PPMD_WSTRING_ARRAY *ppwszDnsServers
    );

uint32_t
netmgr_client_add_dns_domain_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsDomain
    );

uint32_t
netmgr_client_delete_dns_domain_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsDomain
    );

uint32_t
netmgr_client_set_dns_domains_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    PPMD_WSTRING_ARRAY pwszDnsDomains
    );

uint32_t
netmgr_client_get_dns_domains_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    PPMD_WSTRING_ARRAY *ppwszDnsDomains
    );

uint32_t
netmgr_client_get_iaid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t *pdwIaid
    );

uint32_t
netmgr_client_set_iaid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t dwIaid
    );

uint32_t
netmgr_client_get_duid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t *ppwszDuid
    );

uint32_t
netmgr_client_set_duid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDuid
    );

uint32_t
netmgr_client_set_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY pwszNtpServers
    );

uint32_t
netmgr_client_add_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY pwszNtpServers
    );

uint32_t
netmgr_client_delete_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY pwszNtpServers
    );

uint32_t
netmgr_client_get_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY *ppwszNtpServers
    );

uint32_t
netmgr_client_set_hostname_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszHostname
    );

uint32_t
netmgr_client_get_hostname_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszHostname
    );

uint32_t
netmgr_client_wait_for_link_up_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t dwTimeout
    );

uint32_t
netmgr_client_wait_for_ip_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t dwTimeout,
    NET_ADDR_TYPE dwAddrTypes
    );

uint32_t
netmgr_client_get_error_info_w(
    PPMDHANDLE hHandle,
    uint32_t nmErrCode,
    wstring_t *ppwszErrInfo
    );

uint32_t
netmgr_client_set_network_param_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszObjectName,
    const wstring_t pwszParamName,
    const wstring_t pwszParamValue
    );

uint32_t
netmgr_client_get_network_param_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszObjectName,
    const wstring_t pwszParamName,
    wstring_t *ppwszParamValue
    );
//pmdrestapi.c
uint32_t
pmd_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

uint32_t
pmd_rest_api_spec(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pmd_rest_server_info(
    void *pInputJson,
    void **ppOutputJson
    );

//utils.c

//pkgmgmtrestapi.c
uint32_t
pkg_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

uint32_t
pkg_rest_get_version(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_get_count(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_get_repolist(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_list(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_install(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_update(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_erase(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_distro_sync(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_downgrade(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
pkg_rest_reinstall(
    void *pInputJson,
    void **ppOutputJson
    );

//pkgmgmtapi.c
unsigned32
pkg_version_s(
    PPMDHANDLE hPMD,
    wstring_t *ppwszVersion
    );
//pkgmgmt privsep related

uint32_t
pkg_search_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    PTDNF_RPC_PKGINFO_ARRAY* pRpcInfo,
    uint32_t* punCount
    );

uint32_t
pkg_list_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_SCOPE nScope,
    PPMD_WSTRING_ARRAY pPkgNameSpecs,
    PTDNF_RPC_PKGINFO_ARRAY* ppInfo
    );

uint32_t
pkg_repolist_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_REPOLISTFILTER nRepoListFilter,
    PTDNF_RPC_REPODATA_ARRAY *ppRpcRepoDataArray
    );

uint32_t
pkg_updateinfo_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY *ppRpcSummary
    );

uint32_t
pkg_updateinfo_summary_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY *ppRpcSummary
    );

uint32_t
pkg_resolve_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_RPC_SOLVED_PKG_INFO *ppRpcSolvedInfo
    );

uint32_t
pkg_alter_w(
    PPMDHANDLE hHandle,
    PPKGHANDLE hPkgHandle,
    TDNF_ALTERTYPE nAlterType
    );

uint32_t
pkg_version_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszVersion
    );

uint32_t
pkg_get_error_string_w(
    PPMDHANDLE hHandle,
    uint32_t dwErrorCode,
    wstring_t *ppwszError
    );
//firewall_restapi.c
uint32_t
firewall_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

//usrmgmt_restapi.c
uint32_t
usrmgmt_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

//pkgmgmtrpcapi.c
uint32_t
pkg_rpc_get_cmd_args(
    PTDNF_RPC_CMD_ARGS pRpcArgs,
    PTDNF_CMD_ARGS *ppArgs
    );

uint32_t
pkg_get_scope_from_string(
    const char *pszScope,
    TDNF_SCOPE *pnScope
    );

uint32_t
rolemgmt_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

void
TDNFFreeCmdArgs(
    PTDNF_CMD_ARGS pCmdArgs
    );

//config.c
uint32_t
pmd_read_config(
    const char* pszFile,
    const char* pszGroup,
    PPMD_CONFIG* ppConf
    );

void
pmd_free_config(
    PPMD_CONFIG pConf
    );

//utils.c
uint32_t
PPMDGetHostName(
    char** ppszHostName
);

//restserver.c
uint32_t
StartRestServer(
    );

void
StopRestServer(
    );

//server.c
void
pmd_free_server_env(
    PSERVER_ENV pEnv
    );

//rest_s.c
uint32_t
open_privsep_rest(
    const char *pszModule,
    PREST_AUTH pRestAuth,
    PPMDHANDLE *phPMD
    );

//fwmgmt_restapi.c
uint32_t
firewall_rest_get_version(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_get_rules(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_get_rules6(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_put_rules(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_delete_rules(
    void *pInputJson,
    void **ppOutputJson
    );

//usermgmt_restapi.c
uint32_t
usrmgmt_rest_get_users(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_get_userid(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_put_user(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_delete_user(
    void *pInputJson,
    void **ppOutputJson
    );
//groups
uint32_t
usrmgmt_rest_get_groups(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_get_groupid(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
usrmgmt_rest_put_group(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_delete_group(
    void *pInputJson,
    void **ppOutputJson
    );
//usermgmt_api.c
uint32_t
usermgmt_get_version_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszVersion
    );

uint32_t
usermgmt_get_userid_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName,
    uint32_t *pnUID
    );

uint32_t
usermgmt_get_groupid_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName,
    uint32_t *pnGID
    );

void
pmd_free_rest_config(
    PPMD_REST_CONFIG pRestConf
    );

void
pmd_free_roles_config(
    PPMD_ROLES_CONFIG pRolesConf
    );

//utils.c
uint32_t
usermgmt_get_users_w(
    PPMDHANDLE hHandle,
    PPMD_RPC_USER_ARRAY *ppRpcUsers
    );

uint32_t
usermgmt_get_groups_w(
    PPMDHANDLE hHandle,
    PPMD_RPC_GROUP_ARRAY *ppRpcGroups
    );

uint32_t
usermgmt_add_user_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    );

uint32_t
usermgmt_delete_user_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    );

//rolemgmt_api.c
uint32_t
pmd_rolemgmt_load(
    );

uint32_t
pmd_rolemgmt_unload(
    );

//restserver.c
uint32_t
usermgmt_add_group_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    );

uint32_t
usermgmt_delete_group_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszName
    );
//privsephandlelist.c
uint32_t
privsep_handle_list_add(
    PPMDHANDLE hPMD,
    PPKGHANDLE hPkg
    );

uint32_t
privsep_handle_list_get(
    PPKGHANDLE hPkg,
    PPMDHANDLE *phPMD
    );

uint32_t
privsep_handle_list_remove(
    PPKGHANDLE hPkg,
    PPMDHANDLE *phPMD
    );
