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
//netmgmtrestapi.c
uint32_t
net_rest_get_registration(
    PREST_MODULE *ppRestModule
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
net_rest_get_firewall_rule(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_put_firewall_rule(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
net_rest_delete_firewall_rule(
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


//pkgmgmtapi.c
unsigned32
pkg_open_handle_s(
    PTDNF_CMD_ARGS pArgs,
    PTDNF *ppTdnf
    );

unsigned32
pkg_close_handle_s(
    PTDNF pTdnf
    );

uint32_t
pkg_get_scope_from_string(
    const char *pszScope,
    TDNF_SCOPE *pnScope
    );

unsigned32
pkg_count_s(
    PTDNF pTdnf,
    unsigned32* pdwCount
    );

unsigned32
pkg_list_s(
    PTDNF pTdnf,
    unsigned32 nScope,
    char **ppszPackageNameSpecs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

unsigned32
pkg_repolist_s(
    PTDNF pTdnf,
    TDNF_REPOLISTFILTER nFilter,
    PTDNF_REPO_DATA *ppRepoData
    );

unsigned32
pkg_info_s(
    PTDNF pTdnf,
    PTDNF_PKG_INFO *ppPkgInfo
    );

unsigned32
pkg_updateinfo_s(
    PTDNF pTdnf,
    TDNF_AVAIL nAvail,
    char **ppszPackageNameSpecs,
    PTDNF_UPDATEINFO_SUMMARY* ppUpdateInfoSummary
    );

unsigned32
pkg_version_s(
    char** ppszVersion
    );

unsigned32
pkg_resolve_s(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedInfo
    );

unsigned32
pkg_alter_s(
    PTDNF pTdnf,
    TDNF_ALTERTYPE nAlterType
    );

unsigned32
pkg_get_error_string_s(
    uint32_t dwErrorCode,
    char **ppszError
    );
//rpc.c
uint32_t
PMDRpcServerConvertPkgInfoArray(
    PTDNF_PKG_INFO pPkgInfo,
    uint32_t dwCount,
    PTDNF_RPC_PKGINFO_ARRAY *ppRpcPkgInfo
    );

uint32_t
PMDRpcServerConvertPkgInfoList(
    PTDNF_PKG_INFO pPkgInfo,
    PTDNF_RPC_PKGINFO_ARRAY *ppRpcPkgInfo
    );

uint32_t
PMDRpcServerCopyStringArray(
    char **ppszStrings,
    PPMD_WSTRING_ARRAY *ppArray
    );

void
PMDRpcServerFreeSolvedInfo(
    PTDNF_RPC_SOLVED_PKG_INFO pSolvedInfo
    );

void
PMDRpcServerFreePkgInfoArray(
    PTDNF_RPC_PKGINFO_ARRAY pPkgInfoArray
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

//signal.c
uint32_t
pmd_handle_signals(
    );

//server.c
void
pmd_free_server_env(
    PSERVER_ENV pEnv
    );
