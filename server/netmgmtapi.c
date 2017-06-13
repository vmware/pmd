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
netmgr_rpc_get_version(
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

    CHECK_RPC_ACCESS(hBinding, dwError);

    pszVersion = PACKAGE_VERSION;
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


/*
 * Interface configuration APIs
 */
unsigned32
netmgr_rpc_set_mac_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszMacAddress
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pwszMacAddress)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszMacAddress)
    {
        dwError = PMDAllocateStringAFromW(pwszMacAddress, &pszMacAddr);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_set_link_mac_addr(pszIfName, pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszMacAddr);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_mac_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszMacAddress
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;
    wstring_t pwszMacAddress = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !ppwszMacAddress)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_link_mac_addr(pszIfName, &pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszMacAddr, &pwszMacAddress);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszMacAddress = pwszMacAddress;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    if (pszMacAddr != NULL)
    {
        free(pszMacAddr);
    }
    return dwError;
error:
    if (ppwszMacAddress)
    {
        ppwszMacAddress = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_set_link_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_MODE linkMode
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_link_mode(pszIfName, linkMode);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_link_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_MODE *pLinkMode
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    NET_LINK_MODE linkMode;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pLinkMode)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_link_mode(pszIfName, &linkMode);
    BAIL_ON_PMD_ERROR(dwError);

    *pLinkMode = linkMode;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pLinkMode)
    {
        *pLinkMode = RPC_LINK_MODE_UNKNOWN;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_set_link_mtu(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 mtu
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_link_mtu(pszIfName, mtu);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_link_mtu(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pMtu
)
{
    uint32_t dwError = 0, mtu;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pMtu)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_link_mtu(pszIfName, &mtu);
    BAIL_ON_PMD_ERROR(dwError);

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
netmgr_rpc_set_link_state(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_STATE linkState
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_link_state(pszIfName, linkState);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_link_state(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_LINK_STATE *pLinkState
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    NET_LINK_STATE linkState;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pLinkState)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_link_state(pszIfName, &linkState);
    BAIL_ON_PMD_ERROR(dwError);

    *pLinkState = linkState;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pLinkState)
    {
        *pLinkState = RPC_LINK_STATE_UNKNOWN;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_ifup(
    handle_t hBinding,
    wstring_t pwszInterfaceName
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_ifup(pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_ifdown(
    handle_t hBinding,
    wstring_t pwszInterfaceName
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_ifdown(pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_link_info(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PNET_RPC_LINK_INFO_ARRAY *ppLinkInfoArray
)
{
    uint32_t dwError = 0, dwCount = 0, i = 0;
    char *pszIfName = NULL;
    NET_LINK_INFO *pLinkInfo = NULL, *cur;
    PNET_RPC_LINK_INFO_ARRAY pLinkInfoArray = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppLinkInfoArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_link_info(pszIfName, &pLinkInfo);
    BAIL_ON_PMD_ERROR(dwError);

    for (cur = pLinkInfo; cur; cur = cur->pNext, dwCount++);

    dwError = PMDRpcServerAllocateMemory(sizeof(NET_RPC_LINK_INFO_ARRAY),
                                         (void **)&pLinkInfoArray);
    BAIL_ON_PMD_ERROR(dwError);

    pLinkInfoArray->dwCount = dwCount;

    if (dwCount)
    {
        dwError = PMDRpcServerAllocateMemory(
                                      dwCount * sizeof(NET_RPC_LINK_INFO),
                                      (void**)&pLinkInfoArray->pRpcLinkInfo);
        BAIL_ON_PMD_ERROR(dwError);

        for (cur = pLinkInfo; cur; cur = cur->pNext, i++)
        {
            dwError = PMDAllocateStringWFromA(cur->pszInterfaceName,
                         &pLinkInfoArray->pRpcLinkInfo[i].pwszInterfaceName);
            BAIL_ON_PMD_ERROR(dwError);
            dwError = PMDAllocateStringWFromA(cur->pszMacAddress,
                         &pLinkInfoArray->pRpcLinkInfo[i].pwszMacAddress);
            BAIL_ON_PMD_ERROR(dwError);
            pLinkInfoArray->pRpcLinkInfo[i].mtu = cur->mtu;
            pLinkInfoArray->pRpcLinkInfo[i].mode =
                                        (NET_RPC_LINK_MODE)cur->mode;
            pLinkInfoArray->pRpcLinkInfo[i].state =
                                        (NET_RPC_LINK_STATE)cur->state;
        }
    }

    *ppLinkInfoArray = pLinkInfoArray;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    nm_free_link_info(pLinkInfo);
    return dwError;
error:
    if (ppLinkInfoArray)
    {
        *ppLinkInfoArray = NULL;
    }
    if (pLinkInfoArray && pLinkInfoArray->pRpcLinkInfo)
    {
        for (i = 0; i < dwCount; i++)
        {
            PMD_SAFE_FREE_MEMORY(
                     pLinkInfoArray->pRpcLinkInfo[i].pwszInterfaceName);
            PMD_SAFE_FREE_MEMORY(
                     pLinkInfoArray->pRpcLinkInfo[i].pwszMacAddress);
        }
        PMD_SAFE_FREE_MEMORY(pLinkInfoArray->pRpcLinkInfo);
    }
    PMD_SAFE_FREE_MEMORY(pLinkInfoArray);
    goto cleanup;
}


/*
 * IP Address configuration APIs
 */
unsigned32
netmgr_rpc_set_ipv4_addr_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_IPV4_ADDR_MODE mode,
    wstring_t pwszIPv4AddrPrefix,
    wstring_t pwszIPv4Gateway
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszIPv4AddrPrefix = NULL;
    char *pszIPv4Gateway = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszIPv4AddrPrefix)
    {
        dwError = PMDAllocateStringAFromW(pwszIPv4AddrPrefix,
                                          &pszIPv4AddrPrefix);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszIPv4Gateway)
    {
        dwError = PMDAllocateStringAFromW(pwszIPv4Gateway, &pszIPv4Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_set_ipv4_addr_gateway(pszIfName,
                                       mode,
                                       pszIPv4AddrPrefix,
                                       pszIPv4Gateway);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIPv4AddrPrefix);
    PMD_SAFE_FREE_MEMORY(pszIPv4Gateway);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_ipv4_addr_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_IPV4_ADDR_MODE *pMode,
    wstring_t *ppwszIPv4AddrPrefix,
    wstring_t *ppwszIPv4Gateway
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    NET_IPV4_ADDR_MODE mode;
    char *pszIPv4AddrPrefix = NULL, *pszIPv4Gateway = NULL;
    wstring_t pwszIPv4AddrPrefix = NULL, pwszIPv4Gateway = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pMode || !ppwszIPv4AddrPrefix ||
        !ppwszIPv4Gateway)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_ipv4_addr_gateway(pszIfName,
                                       &mode,
                                       &pszIPv4AddrPrefix,
                                       &pszIPv4Gateway);
    BAIL_ON_PMD_ERROR(dwError);

    if (pszIPv4AddrPrefix)
    {
        dwError = PMDRpcServerAllocateWFromA(pszIPv4AddrPrefix,
                                             &pwszIPv4AddrPrefix);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIPv4Gateway)
    {
        dwError = PMDRpcServerAllocateWFromA(pszIPv4Gateway, &pwszIPv4Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pMode = mode;
    *ppwszIPv4AddrPrefix = pwszIPv4AddrPrefix;
    *ppwszIPv4Gateway = pwszIPv4Gateway;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    free(pszIPv4AddrPrefix);
    free(pszIPv4Gateway);
    return dwError;
error:
    if (pMode)
    {
        *pMode = RPC_IPV4_ADDR_MODE_NONE;
    }
    if (ppwszIPv4AddrPrefix)
    {
        *ppwszIPv4AddrPrefix = NULL;
    }
    if (ppwszIPv4Gateway)
    {
        *ppwszIPv4Gateway = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_add_static_ipv6_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszIPv6AddrPrefix
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszIPv6AddrPrefix = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pwszIPv6AddrPrefix)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszIPv6AddrPrefix, &pszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_add_static_ipv6_addr(pszIfName, pszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIPv6AddrPrefix);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_delete_static_ipv6_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszIPv6AddrPrefix
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszIPv6AddrPrefix = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pwszIPv6AddrPrefix)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszIPv6AddrPrefix, &pszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_delete_static_ipv6_addr(pszIfName, pszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIPv6AddrPrefix);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_set_ipv6_addr_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 enableDhcp,
    unsigned32 enableAutoconf
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_ipv6_addr_mode(pszIfName, enableDhcp, enableAutoconf);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_ipv6_addr_mode(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pDhcpEnabled,
    unsigned32 *pAutoconfEnabled
)
{
    uint32_t dwError = 0, dhcpEnabled, autoconfEnabled;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_ipv6_addr_mode(pszIfName, &dhcpEnabled, &autoconfEnabled);
    BAIL_ON_PMD_ERROR(dwError);

    if (pDhcpEnabled)
    {
        *pDhcpEnabled = dhcpEnabled;
    }
    if (pAutoconfEnabled)
    {
        *pAutoconfEnabled = autoconfEnabled;
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pDhcpEnabled)
    {
        *pDhcpEnabled = 0;
    }
    if (pAutoconfEnabled)
    {
        *pAutoconfEnabled = 0;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_set_ipv6_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszIPv6Gateway
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL, *pszIPv6Gateway = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszIPv6Gateway)
    {
        dwError = PMDAllocateStringAFromW(pwszIPv6Gateway, &pszIPv6Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_set_ipv6_gateway(pszIfName, pszIPv6Gateway);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIPv6Gateway);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_ipv6_gateway(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszIPv6Gateway
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL, *pszIPv6Gateway = NULL;
    wstring_t pwszIPv6Gateway = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !ppwszIPv6Gateway)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_ipv6_gateway(pszIfName, &pszIPv6Gateway);
    BAIL_ON_PMD_ERROR(dwError);

    if (pszIPv6Gateway)
    {
        dwError = PMDAllocateStringWFromA(pszIPv6Gateway, &pwszIPv6Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppwszIPv6Gateway = pwszIPv6Gateway;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    free(pszIPv6Gateway);
    return dwError;
error:
    if (ppwszIPv6Gateway)
    {
        *ppwszIPv6Gateway = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_get_ip_addr(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 addrTypes,
    NET_RPC_IP_ADDR_ARRAY **ppIpAddrArray
)
{
    uint32_t dwError = 0;
    size_t i, dwCount = 0;
    char *pszIfName = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;
    NET_RPC_IP_ADDR_ARRAY *pIpAddrArray = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppIpAddrArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_ip_addr(pszIfName, addrTypes, &dwCount, &ppIpAddrList);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(NET_RPC_IP_ADDR_ARRAY),
                                         (void **)&pIpAddrArray);
    BAIL_ON_PMD_ERROR(dwError);

    pIpAddrArray->dwCount = dwCount;

    if (dwCount)
    {
        dwError = PMDRpcServerAllocateMemory(dwCount * sizeof(NET_RPC_IP_ADDR),
                                             (void**)&pIpAddrArray->pRpcIpAddr);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < dwCount; i++)
        {
            dwError = PMDAllocateStringWFromA(ppIpAddrList[i]->pszInterfaceName,
                             &pIpAddrArray->pRpcIpAddr[i].pwszInterfaceName);
            BAIL_ON_PMD_ERROR(dwError);

            pIpAddrArray->pRpcIpAddr[i].type = (NET_RPC_ADDR_TYPE)
                                                    ppIpAddrList[i]->type;

            dwError = PMDAllocateStringWFromA(ppIpAddrList[i]->pszIPAddrPrefix,
                             &pIpAddrArray->pRpcIpAddr[i].pwszIPAddrPrefix);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppIpAddrArray = pIpAddrArray;

cleanup:
    for (i = 0; i < dwCount; i++)
    {
        free(ppIpAddrList[i]->pszInterfaceName);
        free(ppIpAddrList[i]->pszIPAddrPrefix);
        free(ppIpAddrList[i]);
    }
    free(ppIpAddrList);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    if (ppIpAddrArray)
    {
        *ppIpAddrArray = NULL;
    }
    if (pIpAddrArray && pIpAddrArray->pRpcIpAddr)
    {
        for (i = 0; i < pIpAddrArray->dwCount; i++)
        {
            PMD_SAFE_FREE_MEMORY(
                     pIpAddrArray->pRpcIpAddr[i].pwszInterfaceName);
            PMD_SAFE_FREE_MEMORY(
                     pIpAddrArray->pRpcIpAddr[i].pwszIPAddrPrefix);
        }
        PMD_SAFE_FREE_MEMORY(pIpAddrArray->pRpcIpAddr);
    }
    PMD_SAFE_FREE_MEMORY(pIpAddrArray);
    goto cleanup;
}


/*
 * Route configuration APIs
 */
unsigned32
netmgr_rpc_add_static_ip_route(
    handle_t hBinding,
    NET_RPC_IP_ROUTE *pIpRoute
)
{
    uint32_t dwError = 0;
    NET_IP_ROUTE ipRoute = {0};

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pIpRoute)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pIpRoute->pwszInterfaceName,
                                      &ipRoute.pszInterfaceName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pIpRoute->pwszDestNetwork,
                                      &ipRoute.pszDestNetwork);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pIpRoute->pwszGateway,
                                      &ipRoute.pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    if (pIpRoute->pwszSourceNetwork)
    {
        dwError = PMDAllocateStringAFromW(pIpRoute->pwszSourceNetwork,
                                          &ipRoute.pszSourceNetwork);
        BAIL_ON_PMD_ERROR(dwError);
    }

    ipRoute.scope = (NET_ROUTE_SCOPE)pIpRoute->scope;
    ipRoute.metric = pIpRoute->dwMetric;
    ipRoute.table = pIpRoute->dwTableId;

    dwError = nm_add_static_ip_route(&ipRoute);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(ipRoute.pszInterfaceName);
    PMD_SAFE_FREE_MEMORY(ipRoute.pszDestNetwork);
    PMD_SAFE_FREE_MEMORY(ipRoute.pszSourceNetwork);
    PMD_SAFE_FREE_MEMORY(ipRoute.pszGateway);
    return dwError;

error:
    goto cleanup;
}

unsigned32
netmgr_rpc_delete_static_ip_route(
    handle_t hBinding,
    NET_RPC_IP_ROUTE *pIpRoute
)
{
    uint32_t dwError = 0;
    NET_IP_ROUTE ipRoute = {0};

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pIpRoute)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pIpRoute->pwszInterfaceName,
                                      &ipRoute.pszInterfaceName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pIpRoute->pwszDestNetwork,
                                      &ipRoute.pszDestNetwork);
    BAIL_ON_PMD_ERROR(dwError);

    if (pIpRoute->pwszGateway)
    {
        dwError = PMDAllocateStringAFromW(pIpRoute->pwszGateway,
                                          &ipRoute.pszGateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pIpRoute->pwszSourceNetwork)
    {
        dwError = PMDAllocateStringAFromW(pIpRoute->pwszSourceNetwork,
                                          &ipRoute.pszSourceNetwork);
        BAIL_ON_PMD_ERROR(dwError);
    }

    ipRoute.scope = (NET_ROUTE_SCOPE)pIpRoute->scope;
    ipRoute.metric = pIpRoute->dwMetric;
    ipRoute.table = pIpRoute->dwTableId;

    dwError = nm_delete_static_ip_route(&ipRoute);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(ipRoute.pszInterfaceName);
    PMD_SAFE_FREE_MEMORY(ipRoute.pszDestNetwork);
    PMD_SAFE_FREE_MEMORY(ipRoute.pszSourceNetwork);
    PMD_SAFE_FREE_MEMORY(ipRoute.pszGateway);
    return dwError;

error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_static_ip_routes(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_IP_ROUTE_ARRAY **ppIpRouteArray
)
{
    uint32_t dwError = 0;
    size_t i, dwCount = 0;
    char *pszIfName = NULL;
    NET_IP_ROUTE **ppRoutesList = NULL;
    NET_RPC_IP_ROUTE_ARRAY *pIpRouteArray = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppIpRouteArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_static_ip_routes(pszIfName, &dwCount, &ppRoutesList);
    BAIL_ON_PMD_ERROR(dwError);


    dwError = PMDRpcServerAllocateMemory(sizeof(NET_RPC_IP_ROUTE_ARRAY),
                                         (void **)&pIpRouteArray);
    BAIL_ON_PMD_ERROR(dwError);

    pIpRouteArray->dwCount = dwCount;

    if (dwCount)
    {
        dwError = PMDRpcServerAllocateMemory(
                                      dwCount * sizeof(NET_RPC_IP_ROUTE),
                                      (void**)&pIpRouteArray->pRpcIpRoute);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < dwCount; i++)
        {
            dwError = PMDAllocateStringWFromA(ppRoutesList[i]->pszInterfaceName,
                             &pIpRouteArray->pRpcIpRoute[i].pwszInterfaceName);
            BAIL_ON_PMD_ERROR(dwError);
            dwError = PMDAllocateStringWFromA(ppRoutesList[i]->pszDestNetwork,
                             &pIpRouteArray->pRpcIpRoute[i].pwszDestNetwork);
            BAIL_ON_PMD_ERROR(dwError);
            dwError = PMDAllocateStringWFromA(ppRoutesList[i]->pszGateway,
                             &pIpRouteArray->pRpcIpRoute[i].pwszGateway);
            BAIL_ON_PMD_ERROR(dwError);
            if (ppRoutesList[i]->pszSourceNetwork)
            {
                dwError = PMDAllocateStringWFromA(
                             ppRoutesList[i]->pszSourceNetwork,
                             &pIpRouteArray->pRpcIpRoute[i].pwszSourceNetwork);
                BAIL_ON_PMD_ERROR(dwError);
            }
            pIpRouteArray->pRpcIpRoute[i].scope = (NET_RPC_ROUTE_SCOPE)
                                                       ppRoutesList[i]->scope;
            pIpRouteArray->pRpcIpRoute[i].dwMetric = ppRoutesList[i]->metric;
            pIpRouteArray->pRpcIpRoute[i].dwTableId = ppRoutesList[i]->table;
        }
    }

    *ppIpRouteArray = pIpRouteArray;

cleanup:
    for (i = 0; i < dwCount; i++)
    {
        free(ppRoutesList[i]->pszInterfaceName);
        free(ppRoutesList[i]->pszDestNetwork);
        free(ppRoutesList[i]->pszSourceNetwork);
        free(ppRoutesList[i]->pszGateway);
        free(ppRoutesList[i]);
    }
    free(ppRoutesList);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    if (ppIpRouteArray)
    {
        *ppIpRouteArray = NULL;
    }
    if (pIpRouteArray && pIpRouteArray->pRpcIpRoute)
    {
        for (i = 0; i < pIpRouteArray->dwCount; i++)
        {
            PMD_SAFE_FREE_MEMORY(
                     pIpRouteArray->pRpcIpRoute[i].pwszInterfaceName);
            PMD_SAFE_FREE_MEMORY(
                     pIpRouteArray->pRpcIpRoute[i].pwszDestNetwork);
            PMD_SAFE_FREE_MEMORY(
                     pIpRouteArray->pRpcIpRoute[i].pwszSourceNetwork);
            PMD_SAFE_FREE_MEMORY(
                     pIpRouteArray->pRpcIpRoute[i].pwszGateway);
        }
        PMD_SAFE_FREE_MEMORY(pIpRouteArray->pRpcIpRoute);
    }
    PMD_SAFE_FREE_MEMORY(pIpRouteArray);
    goto cleanup;
}


/*
 * DNS configuration APIs
 */
unsigned32
netmgr_rpc_set_dns_servers(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_DNS_MODE dwMode,
    PPMD_WSTRING_ARRAY pwszDnsServers
)
{
    uint32_t i, dwError = 0;
    char *pszIfName = NULL;
    char **ppszDnsServers = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszDnsServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszDnsServers->dwCount)
    {
        dwError = PMDAllocateMemory(sizeof(char *) * pwszDnsServers->dwCount,
                                    (void **)&ppszDnsServers);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszDnsServers->dwCount; ++i)
        {
            dwError = PMDAllocateStringAFromW(pwszDnsServers->ppwszStrings[i],
                                              &ppszDnsServers[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = nm_set_dns_servers(pszIfName,
                                 dwMode,
                                 pwszDnsServers->dwCount,
                                 (const char **)ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if ((pwszDnsServers != NULL) && (ppszDnsServers != NULL))
    {
        for (i = 0; i < pwszDnsServers->dwCount; i++)
        {
            PMD_SAFE_FREE_MEMORY(ppszDnsServers[i]);
        }
        PMD_SAFE_FREE_MEMORY(ppszDnsServers);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_dns_servers(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    NET_RPC_DNS_MODE *pdwMode,
    PPMD_WSTRING_ARRAY *ppwszDnsServers
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    NET_DNS_MODE mode;
    size_t i, bytes = 0, count = 0;
    char **ppszDnsServers = NULL, *pszDnsServers = NULL;
    PPMD_WSTRING_ARRAY pwszDnsServers = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pdwMode || !ppwszDnsServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_dns_servers(pszIfName,
                                 &mode,
                                 &count,
                                 &ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

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
        }
        pwszDnsServers->dwCount = count;
    }

    *pdwMode = mode;
    *ppwszDnsServers = pwszDnsServers;

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsServers, count);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    if (pdwMode)
    {
        *pdwMode = RPC_DNS_MODE_INVALID;
    }
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
netmgr_rpc_set_dns_domains(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PPMD_WSTRING_ARRAY pwszDnsDomains
)
{
    uint32_t i, dwError = 0;
    char *pszIfName = NULL;
    char **ppszDnsDomains = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszDnsDomains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszDnsDomains->dwCount)
    {
        dwError = PMDAllocateMemory(sizeof(char *) * pwszDnsDomains->dwCount,
                                    (void **)&ppszDnsDomains);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszDnsDomains->dwCount; ++i)
        {
            dwError = PMDAllocateStringAFromW(pwszDnsDomains->ppwszStrings[i],
                                              &ppszDnsDomains[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = nm_set_dns_domains(pszIfName,
                                 pwszDnsDomains->dwCount,
                                 (const char **)ppszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if ((pwszDnsDomains != NULL) && (ppszDnsDomains != NULL))
    {
        for (i = 0; i < pwszDnsDomains->dwCount; i++)
        {
            PMD_SAFE_FREE_MEMORY(ppszDnsDomains[i]);
        }
        PMD_SAFE_FREE_MEMORY(ppszDnsDomains);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;

error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_dns_domains(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    PPMD_WSTRING_ARRAY *ppwszDnsDomains
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    size_t i, bytes = 0, count = 0;
    char **ppszDnsDomains = NULL;
    PPMD_WSTRING_ARRAY pwszDnsDomains = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppwszDnsDomains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_dns_domains(pszIfName, &count, &ppszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

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
        }
        pwszDnsDomains->dwCount = count;
    }

    *ppwszDnsDomains = pwszDnsDomains;

cleanup:
    for (i = 0; i < count; i++)
    {
        free(ppszDnsDomains[i]);
    }
    free(ppszDnsDomains);
    PMD_SAFE_FREE_MEMORY(pszIfName);
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
netmgr_rpc_set_iaid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 dwIaid
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_iaid(pszIfName, (uint32_t)dwIaid);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_iaid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 *pdwIaid
)
{
    uint32_t dwError = 0, iaid = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName || !pdwIaid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_iaid(pszIfName, &iaid);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwIaid = (unsigned32)iaid;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    if (pdwIaid)
    {
        *pdwIaid = 0;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_set_duid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t pwszDuid
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszDuid = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszDuid)
    {
        dwError = PMDAllocateStringAFromW(pwszDuid, &pszDuid);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_set_duid(pszIfName, pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDuid);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_duid(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    wstring_t *ppwszDuid
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;
    char *pszDuid = NULL;
    wstring_t pwszDuid = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppwszDuid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszInterfaceName)
    {
        dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_duid(pszIfName, &pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszDuid, &pwszDuid);
    BAIL_ON_PMD_ERROR(dwError);
    *ppwszDuid = pwszDuid;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    if (pszDuid != NULL)
    {
        free(pszDuid);
    }
    return dwError;
error:
    if (ppwszDuid)
    {
        ppwszDuid = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_rpc_set_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    uint32_t dwError = 0;
    char **ppszNtpServers = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszNtpServers->dwCount)
    {
        size_t i = 0;
        dwError = PMDAllocateMemory(
                      sizeof(char *) * pwszNtpServers->dwCount + 1,
                      (void **)&ppszNtpServers);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszNtpServers->dwCount; ++i)
        {
            dwError = PMDAllocateStringAFromW(pwszNtpServers->ppwszStrings[i],
                                              &ppszNtpServers[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = nm_set_ntp_servers(pwszNtpServers->dwCount,
                                 (const char **)ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArray(ppszNtpServers);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_rpc_add_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    uint32_t dwError = 0;
    char **ppszNtpServers = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszNtpServers->dwCount)
    {
        size_t i = 0;
        dwError = PMDAllocateMemory(
                      sizeof(char *) * pwszNtpServers->dwCount + 1,
                      (void **)&ppszNtpServers);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszNtpServers->dwCount; ++i)
        {
            dwError = PMDAllocateStringAFromW(pwszNtpServers->ppwszStrings[i],
                                              &ppszNtpServers[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = nm_add_ntp_servers(pwszNtpServers->dwCount,
                                 (const char **)ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArray(ppszNtpServers);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_rpc_delete_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    uint32_t dwError = 0;
    char **ppszNtpServers = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pwszNtpServers->dwCount)
    {
        size_t i = 0;
        dwError = PMDAllocateMemory(
                      sizeof(char *) * pwszNtpServers->dwCount + 1,
                      (void **)&ppszNtpServers);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszNtpServers->dwCount; ++i)
        {
            dwError = PMDAllocateStringAFromW(pwszNtpServers->ppwszStrings[i],
                                              &ppszNtpServers[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = nm_delete_ntp_servers(pwszNtpServers->dwCount,
                                    (const char **)ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArray(ppszNtpServers);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_ntp_servers(
    handle_t hBinding,
    PPMD_WSTRING_ARRAY *ppwszNtpServers
    )
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    char **ppszNtpServers = NULL;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_ntp_servers(&nCount, &ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                         (void **)&pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (nCount > 0)
    {
        int i = 0;
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
        }
        pwszNtpServers->dwCount = nCount;
    }

    *ppwszNtpServers = pwszNtpServers;

cleanup:
    PMDFreeStringArrayWithCount(ppszNtpServers, nCount);
    return dwError;

error:
    if (ppwszNtpServers)
    {
        *ppwszNtpServers = NULL;
    }
    if (pwszNtpServers != NULL)
    {
        int i = 0;
        for (i = 0; i < pwszNtpServers->dwCount; i++)
        {
            PMDRpcServerFreeMemory(pwszNtpServers->ppwszStrings[i]);
        }
        PMDRpcServerFreeMemory(pwszNtpServers->ppwszStrings);
        PMDRpcServerFreeMemory(pwszNtpServers);
    }
    goto cleanup;
}


/*
 * Misc APIs
 */
unsigned32
netmgr_rpc_set_hostname(
    handle_t hBinding,
    wstring_t pwszHostname
    )
{
    uint32_t dwError = 0;
    char *pszHostname = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszHostname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszHostname, &pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_hostname(pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszHostname);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_hostname(
    handle_t hBinding,
    wstring_t *ppwszHostname
    )
{
    uint32_t dwError = 0;
    char *pszHostname = NULL;
    wstring_t pwszHostname = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppwszHostname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_hostname(&pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszHostname, &pwszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszHostname = pwszHostname;

cleanup:
    if (pszHostname != NULL)
    {
        free(pszHostname);
    }
    return dwError;
error:
    if (ppwszHostname)
    {
        ppwszHostname = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_wait_for_link_up(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 dwTimeout
    )
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_wait_for_link_up(pszIfName, (uint32_t)dwTimeout);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_wait_for_ip(
    handle_t hBinding,
    wstring_t pwszInterfaceName,
    unsigned32 dwTimeout,
    NET_RPC_ADDR_TYPE dwAddrTypes
)
{
    uint32_t dwError = 0;
    char *pszIfName = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszInterfaceName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszInterfaceName, &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_wait_for_ip(pszIfName,
                             (uint32_t)dwTimeout,
                             (NET_ADDR_TYPE)dwAddrTypes);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_error_info(
    handle_t hBinding,
    unsigned32 nmErrCode,
    wstring_t *ppwszErrInfo
)
{
    uint32_t dwError = 0;
    const char *pszErrInfo = NULL;
    wstring_t pwszErrInfo = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!ppwszErrInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszErrInfo = nm_get_error_info(nmErrCode);
    if (pszErrInfo == NULL)
    {
        dwError = ERROR_PMD_NO_DATA;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDRpcServerAllocateWFromA(pszErrInfo, &pwszErrInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszErrInfo = pwszErrInfo;

cleanup:
    return dwError;
error:
    if (ppwszErrInfo)
    {
        ppwszErrInfo = NULL;
    }
    goto cleanup;
}

unsigned32
netmgr_rpc_set_network_param(
    handle_t hBinding,
    wstring_t pwszObjectName,
    wstring_t pwszParamName,
    wstring_t pwszParamValue
)
{
    uint32_t dwError = 0;
    char *pszObjectName = NULL, *pszParamName = NULL, *pszParamValue = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszObjectName || !pwszParamName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszObjectName, &pszObjectName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszParamName, &pszParamName);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszParamValue)
    {
        dwError = PMDAllocateStringAFromW(pwszParamValue, &pszParamValue);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_set_network_param(pszObjectName, pszParamName, pszParamValue);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszParamValue);
    PMD_SAFE_FREE_MEMORY(pszParamName);
    PMD_SAFE_FREE_MEMORY(pszObjectName);
    return dwError;
error:
    goto cleanup;
}

unsigned32
netmgr_rpc_get_network_param(
    handle_t hBinding,
    wstring_t pwszObjectName,
    wstring_t pwszParamName,
    wstring_t *ppwszParamValue
)
{
    uint32_t dwError = 0;
    char *pszObjectName = NULL, *pszParamName = NULL, *pszParamValue = NULL;
    wstring_t pwszParamValue = NULL;

    CHECK_RPC_ACCESS(hBinding, dwError);

    if (!pwszObjectName || !pwszParamName || !ppwszParamValue)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringAFromW(pwszObjectName, &pszObjectName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszParamName, &pszParamName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_network_param(pszObjectName, pszParamName, &pszParamValue);
    BAIL_ON_PMD_ERROR(dwError);

    if (pszParamValue)
    {
        dwError = PMDAllocateStringWFromA(pszParamValue, &pwszParamValue);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppwszParamValue = pwszParamValue;

cleanup:
    if (pszParamValue != NULL)
    {
        free(pszParamValue);
    }
    PMD_SAFE_FREE_MEMORY(pszParamName);
    PMD_SAFE_FREE_MEMORY(pszObjectName);
    return dwError;
error:
    if (ppwszParamValue)
    {
        ppwszParamValue = NULL;
    }
    goto cleanup;
}
