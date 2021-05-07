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


#include "includes.h"

unsigned32
netmgr_privsep_rpc_get_version(
    handle_t hBinding,
    wstring_t* ppwszVersion
    )
{
    uint32_t dwError = 0;
    const char* pszVersion = NULL;
    wstring_t pwszVersion = NULL;

    if(!hBinding || !ppwszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    /* TODO: Should be coming from network-config-manager get_version API */
    pszVersion = NET_API_VERSION;
    if(IsNullOrEmptyString(pszVersion))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszVersion, &pwszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszVersion = pwszVersion;

cleanup:
    return dwError;

error:
    if(ppwszVersion)
    {
        *ppwszVersion = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pwszVersion);
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_is_networkd_running(
    handle_t hBinding,
    wstring_t* ppwszIsNetworkdRunning
    )
{
    uint32_t dwError = 0;
    const char* pszIsNetworkdRunning = NULL;
    wstring_t pwszIsNetworkdRunning = NULL;

    if(!hBinding || !ppwszIsNetworkdRunning)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    if(ncm_is_netword_running() == true)
    {
        pszIsNetworkdRunning = "Running";
    }
    else
    {
        pszIsNetworkdRunning = "Not Running";
    }

    dwError = PMDRpcServerAllocateWFromA(pszIsNetworkdRunning, &pwszIsNetworkdRunning);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszIsNetworkdRunning = pwszIsNetworkdRunning;

cleanup:
    return dwError;

error:
    if(ppwszIsNetworkdRunning)
    {
        *ppwszIsNetworkdRunning = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pwszIsNetworkdRunning);
    goto cleanup;
}

/*
 * Interface configuration APIs
 */
unsigned32
netmgr_privsep_rpc_set_mac_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszMacAddress
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_mac_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszMacAddress
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;
    wstring_t pwszMacAddress = NULL;

    if (!hBinding || !pwszInterfaceName || !ppwszMacAddress)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_mac(pszIfName, &pszMacAddr) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszMacAddr, &pwszMacAddress);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszMacAddress = pwszMacAddress;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszMacAddr);
    return dwError;
error:
    PMDRpcServerFreeMemory(pwszMacAddress);
    if (ppwszMacAddress)
    {
        *ppwszMacAddress = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_set_link_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_MODE linkMode
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_link_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_MODE *pLinkMode
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_link_mtu(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 mtu
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_configure(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszArgv
)
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    char **ppszArgv = NULL;
    NetmgmtCliManager *pNetCliMgr = NULL;
    uint32_t nCount = 0;

    if (!hBinding || !pwszArgv || (pwszArgv->dwCount == 0))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(char *) * pwszArgv->dwCount,
                                (void **)&ppszArgv);
    BAIL_ON_PMD_ERROR(dwError);
    for (i = 0; i < pwszArgv->dwCount; ++i)
    {
        dwError = PMDAllocateStringAFromW(pwszArgv->ppwszStrings[i],
                                          &ppszArgv[i]);
        BAIL_ON_PMD_ERROR(dwError);
	nCount = nCount + 1;
    }

    dwError = netmgmt_cli_manager_new(&pNetCliMgr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgmt_cli_run_command(pNetCliMgr, pwszArgv->dwCount, ppszArgv);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pNetCliMgr)
    {
	netmgmt_cli_unrefp(&pNetCliMgr);
    }
    PMDFreeStringArrayWithCount(ppszArgv, nCount);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_dhcp_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pDHCPMode
)
{
    uint32_t dwError = 0, nDHCPMode = 0;
    char *pszIfName = NULL;

    if (!hBinding || !pwszInterfaceName || !pDHCPMode)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_dhcp_mode(pszIfName, (int *)&nDHCPMode) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    *pDHCPMode = nDHCPMode;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pDHCPMode)
    {
        *pDHCPMode = 0;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_dhcp4_client_identifier(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszDHCP4ClientIndentifier
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszDHCP4ClientIndentifier = NULL;
    wstring_t pwszDHCP4ClientIndentifier = NULL;

    if (!hBinding || !pwszInterfaceName || !ppwszDHCP4ClientIndentifier)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_dhcp4_client_identifier(pszIfName, &pszDHCP4ClientIndentifier) < 0)
    {
       dwError = ERROR_PMD_NET_CMD_FAIL;
       BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszDHCP4ClientIndentifier, &pwszDHCP4ClientIndentifier);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszDHCP4ClientIndentifier = pwszDHCP4ClientIndentifier;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDHCP4ClientIndentifier);
    return dwError;
error:
    PMDRpcServerFreeMemory(pwszDHCP4ClientIndentifier);
    if (ppwszDHCP4ClientIndentifier)
    {
        *ppwszDHCP4ClientIndentifier = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_dhcp_client_iaid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pIaid
)
{
    uint32_t dwError = 0, dwIaid = 0;
    char *pszIfName = NULL;

    if (!hBinding || !pwszInterfaceName || !pIaid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_dhcp_client_iaid(pszIfName, &dwIaid) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    *pIaid = dwIaid;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pIaid)
    {
        *pIaid = 0;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_link_mtu(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pMtu
)
{
    uint32_t dwError = 0, mtu = 0;
    char *pszIfName = NULL;

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    if (!hBinding || !pwszInterfaceName || !pMtu)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_mtu(pszIfName, &mtu) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    *pMtu = mtu;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pMtu)
    {
        *pMtu = 0;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_set_link_state(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_STATE linkState
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_link_state(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_STATE *pLinkState
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_ifup(
    handle_t hBinding,
    wstring_t pwszInterfaceName
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_ifdown(
    handle_t hBinding,
    wstring_t pwszInterfaceName
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_link_info(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PNET_RPC_LINK_INFO_ARRAY *ppLinkInfoArray
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}


/*
 * IP Address configuration APIs
 */
unsigned32
netmgr_privsep_rpc_set_ipv4_addr_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_IPV4_ADDR_MODE mode,
    wstring_t pwszIPv4AddrPrefix,
    wstring_t pwszIPv4Gateway
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_ipv4_addr_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_IPV4_ADDR_MODE *pMode,
    wstring_t *ppwszIPv4AddrPrefix,
    wstring_t *ppwszIPv4Gateway
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_add_static_ipv6_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszIPv6AddrPrefix
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_delete_static_ipv6_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszIPv6AddrPrefix
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_ipv6_addr_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 enableDhcp,
    unsigned32 enableAutoconf
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_ipv6_addr_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pDhcpEnabled,
    unsigned32 *pAutoconfEnabled
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_ipv6_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszIPv6Gateway
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_ipv6_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszIPv6Gateway
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_ip_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 addrTypes,
    NET_RPC_IP_ADDR_ARRAY **ppIpAddrArray
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}


/*
 * Route configuration APIs
 */
unsigned32
netmgr_privsep_rpc_add_static_ip_route(
    handle_t hBinding,
    NET_RPC_IP_ROUTE *pIpRoute
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_delete_static_ip_route(
    handle_t hBinding,
    NET_RPC_IP_ROUTE *pIpRoute
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_static_ip_routes(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_IP_ROUTE_ARRAY **ppIpRouteArray
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}


/*
 * DNS configuration APIs
 */
unsigned32
netmgr_privsep_rpc_add_dns_server(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszDnsServer
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_delete_dns_server(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszDnsServer
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_dns_servers(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_DNS_MODE dwMode,
    PPMD_WSTRING_ARRAY pwszDnsServers
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_dns_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY *ppwszDnsServers
)
{
    uint32_t dwError = 0;
    size_t i, count = 0;
    char **ppszDnsServers = NULL, *pszDnsServers = NULL;
    PPMD_WSTRING_ARRAY pwszDnsServers = NULL;

    if (!hBinding || !ppwszDnsServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_get_dns_server(&ppszDnsServers) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }
    if (ppszDnsServers)
    {
	count = g_strv_length(ppszDnsServers);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pwszDnsServers->dwCount = 0;
    if (count > 0)
    {
        dwError = PMDRpcServerAllocateMemory(sizeof(wstring_t) * count,
                                      (void **)&pwszDnsServers->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < count; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(ppszDnsServers[i],
                                          &pwszDnsServers->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszDnsServers->dwCount = pwszDnsServers->dwCount + 1;
        }
    }

    *ppwszDnsServers = pwszDnsServers;

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsServers, count);
    return dwError;

error:
    if (ppwszDnsServers)
    {
        *ppwszDnsServers = NULL;
    }
    if (pwszDnsServers != NULL)
    {
        for (i = 0; i < pwszDnsServers->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszDnsServers->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszDnsServers->ppwszStrings);
        PMDRpcServerFreeMemory(pwszDnsServers);
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_add_dns_domain(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszDnsDomain
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_delete_dns_domain(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszDnsDomain
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_dns_domains(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PPMD_WSTRING_ARRAY pwszDnsDomains
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_dns_domains(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY *ppwszDnsDomains
)
{
    uint32_t dwError = 0;
    size_t i, count = 0;
    char **ppszDnsDomains = NULL;
    PPMD_WSTRING_ARRAY pwszDnsDomains = NULL;

    if (!hBinding || !ppwszDnsDomains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_get_dns_domains(&ppszDnsDomains) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    if (ppszDnsDomains)
    {
	count = g_strv_length(ppszDnsDomains);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    pwszDnsDomains->dwCount = 0;
    if (count > 0)
    {
        dwError = PMDRpcServerAllocateMemory(sizeof(wstring_t) * count,
                                    (void **)&pwszDnsDomains->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < count; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(ppszDnsDomains[i],
                                              &pwszDnsDomains->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszDnsDomains->dwCount = pwszDnsDomains->dwCount + 1;
        }
    }

    *ppwszDnsDomains = pwszDnsDomains;

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsDomains, count);
    return dwError;

error:
    if (ppwszDnsDomains)
    {
        *ppwszDnsDomains = NULL;
    }
    if (pwszDnsDomains != NULL)
    {
        for (i = 0; i < pwszDnsDomains->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszDnsDomains->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszDnsDomains->ppwszStrings);
        PMDRpcServerFreeMemory(pwszDnsDomains);
    }
    goto cleanup;
}


/*
 * DHCP options, DUID, IAID configuration APIs
 */
unsigned32
netmgr_privsep_rpc_set_iaid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 dwIaid
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_iaid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pdwIaid
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_duid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszDuid
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_duid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszDuid
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

uint32_t
netmgr_privsep_rpc_set_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

uint32_t
netmgr_privsep_rpc_add_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

uint32_t
netmgr_privsep_rpc_delete_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_addresses(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PPMD_WSTRING_ARRAY *ppwszAddresses
    )
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    char *pszIfName = NULL;
    char **ppszAddresses = NULL;
    PPMD_WSTRING_ARRAY pwszAddresses = NULL;

    if (!hBinding || !ppwszAddresses || !pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_addresses(pszIfName, &ppszAddresses) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    if (ppszAddresses)
    {
	nCount = g_strv_length(ppszAddresses);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszAddresses);
    BAIL_ON_PMD_ERROR(dwError);

    pwszAddresses->dwCount = 0;
    if (nCount > 0)
    {
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(wstring_t) * nCount,
                      (void **)&pwszAddresses->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          ppszAddresses[i],
                          &pwszAddresses->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszAddresses->dwCount = pwszAddresses->dwCount + 1;
        }
    }

    *ppwszAddresses = pwszAddresses;

cleanup:
    PMDFreeStringArrayWithCount(ppszAddresses, nCount);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    if (ppwszAddresses)
    {
        *ppwszAddresses = NULL;
    }
    if (pwszAddresses != NULL)
    {
        for (i = 0; i < pwszAddresses->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszAddresses->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszAddresses->ppwszStrings);
        PMDRpcServerFreeMemory(pwszAddresses);
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_routes(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PPMD_WSTRING_ARRAY *ppwszRoutes
    )
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    char *pszIfName = NULL;
    char **ppszRoutes = NULL;
    PPMD_WSTRING_ARRAY pwszRoutes = NULL;

    if (!hBinding || !ppwszRoutes || !pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_routes(pszIfName, &ppszRoutes) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    if (ppszRoutes)
    {
	nCount = g_strv_length(ppszRoutes);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszRoutes);
    BAIL_ON_PMD_ERROR(dwError);

    pwszRoutes->dwCount = 0;
    if (nCount > 0)
    {
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(wstring_t) * nCount,
                      (void **)&pwszRoutes->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          ppszRoutes[i],
                          &pwszRoutes->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszRoutes->dwCount = pwszRoutes->dwCount + 1;
        }
    }

    *ppwszRoutes = pwszRoutes;

cleanup:
    PMDFreeStringArrayWithCount(ppszRoutes, nCount);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    if (ppwszRoutes)
    {
        *ppwszRoutes = NULL;
    }
    if (pwszRoutes != NULL)
    {
        for (i = 0; i < pwszRoutes->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszRoutes->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszRoutes->ppwszStrings);
        PMDRpcServerFreeMemory(pwszRoutes);
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_ntp_servers(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PPMD_WSTRING_ARRAY *ppwszNtpServers
    )
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    char *pszIfName = NULL;
    char **ppszNtpServers = NULL;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;

    if (!hBinding || !pwszInterfaceName || !ppwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_link_get_ntp(pszIfName, &ppszNtpServers) < 0)
    {
	dwError = ERROR_PMD_NET_CMD_FAIL;
	BAIL_ON_PMD_ERROR(dwError);
    }

    if (ppszNtpServers)
    {
	nCount = g_strv_length(ppszNtpServers);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    pwszNtpServers->dwCount = 0;
    if (nCount > 0)
    {
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(wstring_t) * nCount,
                      (void **)&pwszNtpServers->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          ppszNtpServers[i],
                          &pwszNtpServers->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszNtpServers->dwCount = pwszNtpServers->dwCount + 1;
        }
    }
    *ppwszNtpServers = pwszNtpServers;

cleanup:
    PMDFreeStringArrayWithCount(ppszNtpServers, nCount);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    if (ppwszNtpServers)
    {
        *ppwszNtpServers = NULL;
    }
    if (pwszNtpServers != NULL)
    {
        for (i = 0; i < pwszNtpServers->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszNtpServers->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszNtpServers->ppwszStrings);
        PMDRpcServerFreeMemory(pwszNtpServers);
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_nft_get_tables(
    handle_t hBinding,
    wstring_t pwszFamily,
    wstring_t pwszTable,
    PPMD_WSTRING_ARRAY *ppwszNftables
    )
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    char *pszFamily = NULL;
    char *pszTable = NULL;
    char **ppszNftables = NULL;
    PPMD_WSTRING_ARRAY pwszNftables = NULL;

    if (!hBinding || !pwszFamily || !pwszTable || !ppwszNftables)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszFamily, &pszFamily);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszTable, &pszTable);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_nft_get_tables(pszFamily, pszTable, &ppszNftables) < 0)
    {
       dwError = ERROR_PMD_NET_CMD_FAIL;
       BAIL_ON_PMD_ERROR(dwError);
    }

    if (ppszNftables)
    {
       nCount = g_strv_length(ppszNftables);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszNftables);
    BAIL_ON_PMD_ERROR(dwError);

    pwszNftables->dwCount = 0;
    if (nCount > 0)
    {
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(wstring_t) * nCount,
                      (void **)&pwszNftables->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          ppszNftables[i],
                          &pwszNftables->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszNftables->dwCount = pwszNftables->dwCount + 1;
        }
    }
    *ppwszNftables = pwszNftables;

cleanup:
    PMDFreeStringArrayWithCount(ppszNftables, nCount);
    PMD_SAFE_FREE_MEMORY(pszFamily);
    PMD_SAFE_FREE_MEMORY(pszTable);
    return dwError;

error:
    if (ppwszNftables)
    {
        *ppwszNftables = NULL;
    }
    if (pwszNftables != NULL)
    {
        for (i = 0; i < pwszNftables->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszNftables->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszNftables->ppwszStrings);
        PMDRpcServerFreeMemory(pwszNftables);
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_nft_get_chains(
    handle_t hBinding,
    wstring_t pwszFamily,
    wstring_t pwszTable,
    wstring_t pwszChains,
    PPMD_WSTRING_ARRAY *ppwszNftablesChains
    )
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    char *pszFamily = NULL;
    char *pszTable = NULL;
    char *pszChains = NULL;
    char **ppszNftablesChains = NULL;
    PPMD_WSTRING_ARRAY pwszNftablesChains = NULL;

    if (!hBinding || !pwszFamily || !pwszTable || !pwszChains || !ppwszNftablesChains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszFamily, &pszFamily);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszTable, &pszTable);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszChains, &pszChains);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_nft_get_chains(pszFamily, pszTable, pszChains, &ppszNftablesChains) < 0)
    {
       dwError = ERROR_PMD_NET_CMD_FAIL;
       BAIL_ON_PMD_ERROR(dwError);
    }

    if (ppszNftablesChains)
    {
       nCount = g_strv_length(ppszNftablesChains);
    }
    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszNftablesChains);
    BAIL_ON_PMD_ERROR(dwError);

    pwszNftablesChains->dwCount = 0;
    if (nCount > 0)
    {
        dwError = PMDRpcServerAllocateMemory(
                      sizeof(wstring_t) * nCount,
                      (void **)&pwszNftablesChains->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; i++)
        {
            dwError = PMDRpcServerAllocateWFromA(
                          ppszNftablesChains[i],
                          &pwszNftablesChains->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
	    pwszNftablesChains->dwCount = pwszNftablesChains->dwCount + 1;
        }
    }
    *ppwszNftablesChains = pwszNftablesChains;

cleanup:
    PMDFreeStringArrayWithCount(ppszNftablesChains, nCount);
    PMD_SAFE_FREE_MEMORY(pszFamily);
    PMD_SAFE_FREE_MEMORY(pszTable);
    PMD_SAFE_FREE_MEMORY(pszChains);
    return dwError;

error:
    if (ppwszNftablesChains)
    {
        *ppwszNftablesChains = NULL;
    }
    if (pwszNftablesChains != NULL)
    {
        for (i = 0; i < pwszNftablesChains->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszNftablesChains->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszNftablesChains->ppwszStrings);
        PMDRpcServerFreeMemory(pwszNftablesChains);
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_nft_rules(
    handle_t hBinding,
    wstring_t pwszTable,
    wstring_t *ppwszNftableRules
)
{
    uint32_t dwError = 0;
    char *pszTable = NULL;
    char *pszNftableRules = NULL;
    wstring_t pwszNftableRules = NULL;

    if (!hBinding || !pwszTable || !ppwszNftableRules)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszTable, &pszTable);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_get_nft_rules(pszTable, &pszNftableRules) < 0)
    {
       dwError = ERROR_PMD_NET_CMD_FAIL;
       BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszNftableRules, &pwszNftableRules);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszNftableRules = pwszNftableRules;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszTable);
    PMD_SAFE_FREE_MEMORY(pszNftableRules);
    return dwError;
error:
    PMDRpcServerFreeMemory(pwszNftableRules);
    if (ppwszNftableRules)
    {
        *ppwszNftableRules = NULL;
    }
    goto cleanup;
}


/*
 * Misc APIs
 */
unsigned32
netmgr_privsep_rpc_set_hostname(
    handle_t hBinding,
    wstring_t pwszHostname
    )
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_hostname(
    handle_t hBinding,
    wstring_t *ppwszHostname
    )
{
    uint32_t dwError = 0;
    char *pszHostname = NULL;
    wstring_t pwszHostname = NULL;

    if (!hBinding || !ppwszHostname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = ncm_get_system_hostname(&pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszHostname, &pwszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszHostname = pwszHostname;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszHostname);
    return dwError;
error:
    PMDRpcServerFreeMemory(pwszHostname);
    if (ppwszHostname)
    {
        ppwszHostname = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_wait_for_link_up(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 dwTimeout
    )
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_wait_for_ip(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 dwTimeout,
    NET_RPC_ADDR_TYPE dwAddrTypes
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_error_info(
    handle_t hBinding,
    unsigned32 nmErrCode,
    wstring_t *ppwszErrInfo
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_set_network_param(
    handle_t hBinding,
    wstring_t pwszObjectName,
    wstring_t pwszParamName,
    wstring_t pwszParamValue
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_network_param(
    handle_t hBinding,
    wstring_t pwszObjectName,
    wstring_t pwszParamName,
    wstring_t *ppwszParamValue
)
{
    /*
     * TODO: remove this API support,
     * once Python and rest API support
     * is added.
     */
    uint32_t dwError = ERROR_PMD_NET_UNSUPPORTED_CMD;
    return dwError;
}

unsigned32
netmgr_privsep_rpc_get_link_status(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszLinkStatus
    )
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszLinkStatus = NULL;
    wstring_t pwszLinkStatus = NULL;

    if (!hBinding || !pwszInterfaceName || !ppwszLinkStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_get_link_status(pszIfName, &pszLinkStatus) < 0)
    {
        dwError = ERROR_PMD_NET_CMD_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszLinkStatus, &pwszLinkStatus);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszLinkStatus = pwszLinkStatus;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszLinkStatus);
    return dwError;

error:
    PMDRpcServerFreeMemory(pwszLinkStatus);
    if (ppwszLinkStatus)
    {
        *ppwszLinkStatus = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_privsep_rpc_get_system_status(
    handle_t hBinding,
    wstring_t *ppwszSystemStatus
    )
{
    uint32_t dwError = 0;
    char *pszSystemStatus = NULL;
    wstring_t pwszSystemStatus = NULL;

    if (!hBinding || !ppwszSystemStatus)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = check_connection_integrity(hBinding);
    BAIL_ON_PMD_ERROR(dwError);

    if (ncm_get_system_status(&pszSystemStatus) < 0)
    {
        dwError = ERROR_PMD_NET_CMD_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDRpcServerAllocateWFromA(pszSystemStatus, &pwszSystemStatus);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszSystemStatus = pwszSystemStatus;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszSystemStatus);
    return dwError;

error:
    PMDRpcServerFreeMemory(pwszSystemStatus);
    if (ppwszSystemStatus)
    {
        *ppwszSystemStatus = NULL;
    }
    goto cleanup;
}

