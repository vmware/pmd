a/*
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

uint32_t
netmgr_client_set_mac_addr_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszMacAddress
)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname || !pwszMacAddress)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }


    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_mac_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszMacAddress),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_mac_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszMacAddress),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_mac_addr(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    const char *pszMacAddress
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszMacAddress = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszMacAddress, &pwszMacAddress);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_mac_addr_w(hHandle, pwszIfname, pwszMacAddress);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDFreeMemory(pwszMacAddress);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_mac_addr_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    wstring_t *ppwszMacAddress
)
{
    uint32_t dwError = 0;
    wstring_t pwszMacAddress = NULL;

    if(!hHandle || !pwszIfname || !ppwszMacAddress)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_mac_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   &pwszMacAddress),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_mac_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   &pwszMacAddress),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszMacAddress = pwszMacAddress;

cleanup:
    return dwError;

error:
    if (ppwszMacAddress)
    {
        *ppwszMacAddress = NULL;
    }
    PMDRpcClientFreeMemory(pwszMacAddress);
    goto cleanup;
}

uint32_t
netmgr_client_get_mac_addr(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    char **ppszMacAddress
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszMacAddress = NULL;
    char *pszMacAddress = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_mac_addr_w(
                  hHandle,
                  pwszIfname,
                  &pwszMacAddress);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszMacAddress)
    {
        dwError = PMDAllocateStringAFromW(pwszMacAddress,
                                          &pszMacAddress);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszMacAddress = pszMacAddress;

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDRpcClientFreeMemory(pwszMacAddress);
    return dwError;

error:
    if (ppszMacAddress)
    {
        *ppszMacAddress = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszMacAddress);
    goto cleanup;
}

uint32_t
netmgr_client_set_link_mode_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_RPC_LINK_MODE rpcLinkMode
)
{
    uint32_t dwError = 0;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_link_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   rpcLinkMode),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_link_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   rpcLinkMode),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_set_link_mode(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_MODE linkMode
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    NET_RPC_LINK_MODE rpcLinkMode = (NET_RPC_LINK_MODE)linkMode;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_link_mode_w(hHandle, pwszIfname, linkMode);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_get_link_mode_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_RPC_LINK_MODE *pLinkMode
)
{
    uint32_t dwError = 0;
    NET_RPC_LINK_MODE rpcLinkMode = RPC_LINK_MODE_UNKNOWN;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_link_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   &rpcLinkMode),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_link_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   &rpcLinkMode),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pLinkMode = rpcLinkMode;

cleanup:
    return dwError;

error:
    if (pLinkMode)
    {
        *pLinkMode = RPC_LINK_MODE_UNKNOWN;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_link_mode(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_MODE *pLinkMode
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    NET_RPC_LINK_MODE nLinkMode = RPC_LINK_MODE_UNKNOWN;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_mode_w(
                  hHandle,
                  pwszIfname,
                  &nLinkMode);
    BAIL_ON_PMD_ERROR(dwError);

    *pLinkMode = nLinkMode;

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (pLinkMode)
    {
        *pLinkMode = LINK_MODE_UNKNOWN;
    }
    goto cleanup;
}

uint32_t
netmgr_client_set_link_mtu_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t mtu
)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_link_mtu(
                   hHandle->hRpc,
                   pwszIfname,
                   mtu),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_link_mtu(
                   hHandle->hRpc,
                   pwszIfname,
                   mtu),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_set_link_mtu(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    uint32_t mtu
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_link_mtu_w(
                  hHandle,
                  pwszIfname,
                  mtu);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_get_link_mtu_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t *pnMTU
)
{
    uint32_t dwError = 0;
    uint32_t nMTU = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_link_mtu(
                   hHandle->hRpc,
                   pwszIfname,
                   &nMTU),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_link_mtu(
                   hHandle->hRpc,
                   pwszIfname,
                   &nMTU),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pnMTU = nMTU;

cleanup:
    return dwError;

error:
    if (pnMTU)
    {
        *pnMTU = 0;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_link_mtu(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    uint32_t *pnMTU
)
{
    uint32_t dwError = 0;
    uint32_t nMTU = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname) || !pnMTU)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_mtu_w(
                  hHandle,
                  pwszIfname,
                  &nMTU);
    BAIL_ON_PMD_ERROR(dwError);

    *pnMTU = nMTU;

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (pnMTU)
    {
        *pnMTU = 0;
    }
    goto cleanup;
}

uint32_t
netmgr_client_set_link_state_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_LINK_STATE linkState
)
{
    uint32_t dwError = 0;
    NET_RPC_LINK_STATE rpcLinkState = (NET_RPC_LINK_STATE)linkState;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_link_state(
                   hHandle->hRpc,
                   pwszIfname,
                   rpcLinkState),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_link_state(
                   hHandle->hRpc,
                   pwszIfname,
                   rpcLinkState),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_set_link_state(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_STATE linkState
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    NET_RPC_LINK_STATE rpcLinkState = (NET_RPC_LINK_STATE)linkState;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_link_state_w(
                  hHandle,
                  pwszIfname,
                  rpcLinkState);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_get_link_state_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    NET_RPC_LINK_STATE *prpcLinkState
)
{
    uint32_t dwError = 0;
    NET_RPC_LINK_STATE rpcLinkState = RPC_LINK_STATE_UNKNOWN;

    if(!hHandle || !pwszIfname || !prpcLinkState)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_link_state(
                   hHandle->hRpc,
                   pwszIfname,
                   &rpcLinkState),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_link_state(
                   hHandle->hRpc,
                   pwszIfname,
                   &rpcLinkState),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *prpcLinkState = rpcLinkState;

cleanup:
    return dwError;

error:
    if (prpcLinkState)
    {
        *prpcLinkState = RPC_LINK_STATE_UNKNOWN;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_link_state(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_STATE *pLinkState
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    NET_RPC_LINK_STATE rpcLinkState = RPC_LINK_STATE_UNKNOWN;

    if(!hHandle || IsNullOrEmptyString(pszIfname) || !pLinkState)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_state_w(
                  hHandle,
                  pwszIfname,
                  &rpcLinkState);
    BAIL_ON_PMD_ERROR(dwError);

    *pLinkState = (NET_LINK_STATE)rpcLinkState;

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (pLinkState)
    {
        *pLinkState = (int)RPC_LINK_STATE_UNKNOWN;
    }
    goto cleanup;
}

uint32_t
netmgr_client_ifup_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname
)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_ifup(hHandle->hRpc, pwszIfname), dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_ifup(hHandle->hRpc, pwszIfname), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_ifup(
    PPMDHANDLE hHandle,
    const char *pszIfname
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_ifup_w(hHandle, pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_ifdown_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname
)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_ifdown(hHandle->hRpc, pwszIfname), dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_ifdown(hHandle->hRpc, pwszIfname), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_ifdown(
    PPMDHANDLE hHandle,
    const char *pszIfname
)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_ifdown_w(hHandle, pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_get_link_info_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    PNET_RPC_LINK_INFO_ARRAY *ppLinkInfoArray
)
{
    uint32_t dwError = 0, i;
    PNET_RPC_LINK_INFO_ARRAY pLinkInfoArray = NULL;

    if(!hHandle || !ppLinkInfoArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_link_info(
                   hHandle->hRpc,
                   pwszIfname,
                   &pLinkInfoArray),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_link_info(
                   hHandle->hRpc,
                   pwszIfname,
                   &pLinkInfoArray),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    if(!pLinkInfoArray || !pLinkInfoArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppLinkInfoArray = pLinkInfoArray;

cleanup:
    return dwError;

error:
    if (ppLinkInfoArray)
    {
        *ppLinkInfoArray = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_link_info(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    NET_LINK_INFO **ppLinkInfo
)
{
    uint32_t dwError = 0, i;
    wstring_t pwszIfname = NULL;
    NET_LINK_INFO *pLinkInfo = NULL, *pNew = NULL;
    PNET_RPC_LINK_INFO_ARRAY pLinkInfoArray = NULL;

    if(!hHandle || !ppLinkInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_link_info_w(
                  hHandle,
                  pwszIfname,
                  &pLinkInfoArray);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pLinkInfoArray || !pLinkInfoArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for (i = 0; i < pLinkInfoArray->dwCount; i++)
    {
        dwError = PMDAllocateMemory(sizeof(NET_LINK_INFO), (void **)&pNew);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                             pLinkInfoArray->pRpcLinkInfo[i].pwszInterfaceName,
                             &pNew->pszInterfaceName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                             pLinkInfoArray->pRpcLinkInfo[i].pwszMacAddress,
                             &pNew->pszMacAddress);
        BAIL_ON_PMD_ERROR(dwError);

        pNew->mode = (NET_LINK_MODE)pLinkInfoArray->pRpcLinkInfo[i].mode;
        pNew->mtu = pLinkInfoArray->pRpcLinkInfo[i].mtu;
        pNew->state = (NET_LINK_STATE)pLinkInfoArray->pRpcLinkInfo[i].state;
        pNew->pNext = pLinkInfo;
        pLinkInfo = pNew;
        pNew = NULL;
    }

    *ppLinkInfo = pLinkInfo;

cleanup:
    if (pLinkInfoArray)
    {
        for (i = 0; i < pLinkInfoArray->dwCount; i++)
        {
            PMD_SAFE_FREE_MEMORY(
                     pLinkInfoArray->pRpcLinkInfo[i].pwszInterfaceName);
            PMD_SAFE_FREE_MEMORY(
                     pLinkInfoArray->pRpcLinkInfo[i].pwszMacAddress);
        }
        PMD_SAFE_FREE_MEMORY(pLinkInfoArray->pRpcLinkInfo);
    }
    PMD_SAFE_FREE_MEMORY(pLinkInfoArray);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (ppLinkInfo)
    {
        *ppLinkInfo = NULL;
    }
    if (pNew)
    {
        free(pNew->pszInterfaceName);
        free(pNew->pszMacAddress);
        free(pNew);
    }
    for (NET_LINK_INFO *pCur = pLinkInfo; pCur; pCur = pLinkInfo)
    {
        pLinkInfo = pCur->pNext;
        free(pCur->pszMacAddress);
        free(pCur->pszInterfaceName);
        free(pCur);
    }
    goto cleanup;
}


uint32_t
netmgr_client_set_ipv4_addr_gateway_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_IPV4_ADDR_MODE mode,
    wstring_t pwszIPv4AddrPrefix,
    wstring_t pwszIPv4Gateway
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_ipv4_addr_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   (NET_RPC_IPV4_ADDR_MODE)mode,
                   pwszIPv4AddrPrefix,
                   pwszIPv4Gateway),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_ipv4_addr_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   (NET_RPC_IPV4_ADDR_MODE)mode,
                   pwszIPv4AddrPrefix,
                   pwszIPv4Gateway),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ipv4_addr_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_IPV4_ADDR_MODE mode,
    char *pszIPv4AddrPrefix,
    char *pszIPv4Gateway
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszIPv4AddrPrefix = NULL;
    wstring_t pwszIPv4Gateway = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    if (pszIPv4AddrPrefix)
    {
        dwError = PMDAllocateStringWFromA(pszIPv4AddrPrefix,
                                          &pwszIPv4AddrPrefix);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIPv4Gateway)
    {
        dwError = PMDAllocateStringWFromA(pszIPv4Gateway, &pwszIPv4Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_ipv4_addr_gateway_w(
                  hHandle,
                  pwszIfname,
                  (NET_RPC_IPV4_ADDR_MODE)mode,
                  pwszIPv4AddrPrefix,
                  pwszIPv4Gateway);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDRpcClientFreeMemory(pwszIPv4AddrPrefix);
    PMDRpcClientFreeMemory(pwszIPv4Gateway);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_ipv4_addr_gateway_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_RPC_IPV4_ADDR_MODE *pMode,
    wstring_t *ppwszIPv4AddrPrefix,
    wstring_t *ppwszIPv4Gateway
    )
{
    uint32_t dwError = 0;
    NET_RPC_IPV4_ADDR_MODE mode = RPC_IPV4_ADDR_MODE_NONE;
    wstring_t pwszIPv4AddrPrefix = NULL, pwszIPv4Gateway = NULL;

    if(!hHandle || !pwszIfname || !ppwszIPv4AddrPrefix || !ppwszIPv4Gateway)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_ipv4_addr_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   &mode,
                   &pwszIPv4AddrPrefix,
                   &pwszIPv4Gateway),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_ipv4_addr_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   &mode,
                   &pwszIPv4AddrPrefix,
                   &pwszIPv4Gateway),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pMode = mode;
    *ppwszIPv4AddrPrefix = pwszIPv4AddrPrefix;
    *ppwszIPv4Gateway = pwszIPv4Gateway;

cleanup:
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
    PMDRpcClientFreeMemory(pwszIPv4AddrPrefix);
    PMDRpcClientFreeMemory(pwszIPv4Gateway);
    goto cleanup;
}

uint32_t
netmgr_client_get_ipv4_addr_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_IPV4_ADDR_MODE *pMode,
    char **ppszIPv4AddrPrefix,
    char **ppszIPv4Gateway
    )
{
    uint32_t dwError = 0;
    NET_RPC_IPV4_ADDR_MODE mode = RPC_IPV4_ADDR_MODE_NONE;
    wstring_t pwszIfname = NULL;
    wstring_t pwszIPv4AddrPrefix = NULL, pwszIPv4Gateway = NULL;
    char *pszIPv4AddrPrefix = NULL, *pszIPv4Gateway = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszIfname) ||
       !pMode ||
       !ppszIPv4AddrPrefix ||
       !ppszIPv4Gateway)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv4_addr_gateway_w(
                  hHandle,
                  pwszIfname,
                  &mode,
                  &pwszIPv4AddrPrefix,
                  &pwszIPv4Gateway);
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

    *pMode = (NET_IPV4_ADDR_MODE)mode;
    *ppszIPv4AddrPrefix = pszIPv4AddrPrefix;
    *ppszIPv4Gateway = pszIPv4Gateway;

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDRpcClientFreeMemory(pwszIPv4AddrPrefix);
    PMDRpcClientFreeMemory(pwszIPv4Gateway);
    return dwError;

error:
    if (pMode)
    {
        *pMode = RPC_IPV4_ADDR_MODE_NONE;
    }
    if (ppszIPv4AddrPrefix)
    {
        *ppszIPv4AddrPrefix = NULL;
    }
    if (ppszIPv4Gateway)
    {
        *ppszIPv4Gateway = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszIPv4AddrPrefix);
    PMD_SAFE_FREE_MEMORY(pszIPv4Gateway);
    goto cleanup;
}

uint32_t
netmgr_client_add_static_ipv6_addr_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    const wstring_t pwszIPv6AddrPrefix
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname || !pwszIPv6AddrPrefix)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_add_static_ipv6_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszIPv6AddrPrefix),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_add_static_ipv6_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszIPv6AddrPrefix),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_static_ipv6_addr(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszIPv6AddrPrefix
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszIPv6AddrPrefix = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszIfname) ||
       IsNullOrEmptyString(pszIPv6AddrPrefix))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszIPv6AddrPrefix, &pwszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_static_ipv6_addr_w(
                  hHandle,
                  pwszIfname,
                  pwszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDFreeMemory(pwszIPv6AddrPrefix);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_static_ipv6_addr_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszIPv6AddrPrefix
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname || !pwszIPv6AddrPrefix)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_delete_static_ipv6_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszIPv6AddrPrefix),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_delete_static_ipv6_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszIPv6AddrPrefix),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_static_ipv6_addr(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszIPv6AddrPrefix
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszIPv6AddrPrefix = NULL;

    if(!hHandle ||
       IsNullOrEmptyString(pszIfname) ||
       IsNullOrEmptyString(pszIPv6AddrPrefix))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszIPv6AddrPrefix, &pwszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_static_ipv6_addr_w(
                  hHandle,
                  pwszIfname,
                  pwszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDFreeMemory(pwszIPv6AddrPrefix);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ipv6_addr_mode_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_ipv6_addr_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   enableDhcp,
                   enableAutoconf),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_ipv6_addr_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   enableDhcp,
                   enableAutoconf),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ipv6_addr_mode(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t enableDhcp,
    uint32_t enableAutoconf
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_ipv6_addr_mode_w(
               hHandle,
               pwszIfname,
               enableDhcp,
               enableAutoconf);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_ipv6_addr_mode_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
    )
{
    uint32_t dwError = 0;
    unsigned32 dhcpEnabled = 0, autoconfEnabled = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_ipv6_addr_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   &dhcpEnabled,
                   &autoconfEnabled),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_ipv6_addr_mode(
                   hHandle->hRpc,
                   pwszIfname,
                   &dhcpEnabled,
                   &autoconfEnabled),
                   dwError);
    }
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
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_ipv6_addr_mode(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t *pDhcpEnabled,
    uint32_t *pAutoconfEnabled
    )
{
    uint32_t dwError = 0;
    unsigned32 dhcpEnabled = 0, autoconfEnabled = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv6_addr_mode_w(
                  hHandle,
                  pwszIfname,
                  &dhcpEnabled,
                  &autoconfEnabled);
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
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ipv6_gateway_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    const wstring_t pwszIPv6Gateway
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_ipv6_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszIPv6Gateway),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_ipv6_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszIPv6Gateway),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ipv6_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszIPv6Gateway
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL, pwszIPv6Gateway = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    if (pszIPv6Gateway)
    {
        dwError = PMDAllocateStringWFromA(pszIPv6Gateway, &pwszIPv6Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_ipv6_gateway_w(
                  hHandle,
                  pwszIfname,
                  pwszIPv6Gateway);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDFreeMemory(pwszIPv6Gateway);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_ipv6_gateway_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    wstring_t *ppwszIPv6Gateway
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIPv6Gateway = NULL;

    if(!hHandle || !pwszIfname || !ppwszIPv6Gateway)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_ipv6_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   &pwszIPv6Gateway),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_ipv6_gateway(
                   hHandle->hRpc,
                   pwszIfname,
                   &pwszIPv6Gateway),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszIPv6Gateway = pwszIPv6Gateway;

cleanup:
    return dwError;

error:
    if (ppwszIPv6Gateway)
    {
        *ppwszIPv6Gateway = NULL;
    }
    PMDRpcClientFreeMemory(pwszIPv6Gateway);
    goto cleanup;
}

uint32_t
netmgr_client_get_ipv6_gateway(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char **ppszIPv6Gateway
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL, pwszIPv6Gateway = NULL;
    char *pszIPv6Gateway = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname) || !ppszIPv6Gateway)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv6_gateway_w(
               hHandle,
               pwszIfname,
               &pwszIPv6Gateway);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszIPv6Gateway)
    {
        dwError = PMDAllocateStringAFromW(pwszIPv6Gateway, &pszIPv6Gateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszIPv6Gateway = pszIPv6Gateway;

cleanup:
    PMDFreeMemory(pwszIfname);
    PMDRpcClientFreeMemory(pwszIPv6Gateway);
    return dwError;

error:
    if (ppszIPv6Gateway)
    {
        *ppszIPv6Gateway = NULL;
    }
    PMDFreeMemory(pszIPv6Gateway);
    goto cleanup;
}

uint32_t
netmgr_client_get_ip_addr_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t addrTypes,
    NET_RPC_IP_ADDR_ARRAY **ppIpAddrArray
    )
{
    uint32_t dwError = 0;
    NET_RPC_IP_ADDR_ARRAY *pIpAddrArray = NULL;

    if(!hHandle || !ppIpAddrArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_ip_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   addrTypes,
                   &pIpAddrArray),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_ip_addr(
                   hHandle->hRpc,
                   pwszIfname,
                   addrTypes,
                   &pIpAddrArray),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppIpAddrArray = pIpAddrArray;

cleanup:
    return dwError;

error:
    if (ppIpAddrArray)
    {
        *ppIpAddrArray = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_ip_addr(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t addrTypes,
    size_t *pCount,
    NET_IP_ADDR ***pppIpAddrList
    )
{
    uint32_t dwError = 0;
    size_t i;
    wstring_t pwszIfname = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;
    NET_RPC_IP_ADDR_ARRAY *pIpAddrArray = NULL;

    if(!hHandle || !pCount || !pppIpAddrList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname != NULL)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_ip_addr_w(
                  hHandle,
                  pwszIfname,
                  addrTypes,
                  &pIpAddrArray);
    BAIL_ON_PMD_ERROR(dwError);

    if (pIpAddrArray && pIpAddrArray->dwCount)
    {
        dwError = PMDAllocateMemory(sizeof(PNET_IP_ADDR)*pIpAddrArray->dwCount,
                                    (void **)&ppIpAddrList);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pIpAddrArray->dwCount; i++)
        {
            dwError = PMDAllocateMemory(sizeof(NET_IP_ADDR),
                                        (void **)&ppIpAddrList[i]);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = PMDAllocateStringAFromW(
                                 pIpAddrArray->pRpcIpAddr[i].pwszInterfaceName,
                                 &((ppIpAddrList[i])->pszInterfaceName));
            BAIL_ON_PMD_ERROR(dwError);

            ppIpAddrList[i]->type = (NET_ADDR_TYPE)
                                         pIpAddrArray->pRpcIpAddr[i].type;

            dwError = PMDAllocateStringAFromW(
                                 pIpAddrArray->pRpcIpAddr[i].pwszIPAddrPrefix,
                                 &((ppIpAddrList[i])->pszIPAddrPrefix));
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *pCount = (pIpAddrArray != NULL) ? pIpAddrArray->dwCount : 0;
    *pppIpAddrList = ppIpAddrList;

cleanup:
    if (pIpAddrArray && pIpAddrArray->pRpcIpAddr)
    {
        for (i = 0; i < pIpAddrArray->dwCount; i++)
        {
            PMDRpcClientFreeMemory(
                        pIpAddrArray->pRpcIpAddr[i].pwszInterfaceName);
            PMDRpcClientFreeMemory(
                        pIpAddrArray->pRpcIpAddr[i].pwszIPAddrPrefix);
        }
        PMDRpcClientFreeMemory(pIpAddrArray->pRpcIpAddr);
    }
    PMDRpcClientFreeMemory(pIpAddrArray);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (pCount)
    {
        *pCount = 0;
    }
    if (pppIpAddrList)
    {
        *pppIpAddrList = NULL;
    }
    if (pIpAddrArray && ppIpAddrList)
    {
        for (i = 0; i < pIpAddrArray->dwCount; i++)
        {
            if (ppIpAddrList[i] == NULL)
            {
                continue;
            }
            PMDFreeMemory(ppIpAddrList[i]->pszInterfaceName);
            PMDFreeMemory(ppIpAddrList[i]->pszIPAddrPrefix);
            PMDFreeMemory(ppIpAddrList[i]);
        }
        PMDFreeMemory(ppIpAddrList);
    }
    goto cleanup;
}

uint32_t
netmgr_client_add_static_ip_route_w(
    PPMDHANDLE hHandle,
    NET_RPC_IP_ROUTE *pIpRoute
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pIpRoute)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_add_static_ip_route(
                   hHandle->hRpc,
                   pIpRoute),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_add_static_ip_route(
                   hHandle->hRpc,
                   pIpRoute),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_static_ip_route(
    PPMDHANDLE hHandle,
    NET_IP_ROUTE *pIpRoute
    )
{
    uint32_t dwError = 0;
    NET_RPC_IP_ROUTE ipRoute = {0};

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pIpRoute->pszInterfaceName,
                                      &ipRoute.pwszInterfaceName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pIpRoute->pszDestNetwork,
                                      &ipRoute.pwszDestNetwork);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pIpRoute->pszGateway,
                                      &ipRoute.pwszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    if (pIpRoute->pszSourceNetwork)
    {
        dwError = PMDAllocateStringWFromA(pIpRoute->pszSourceNetwork,
                                          &ipRoute.pwszSourceNetwork);
        BAIL_ON_PMD_ERROR(dwError);
    }

    ipRoute.scope = (NET_RPC_ROUTE_SCOPE)pIpRoute->scope;
    ipRoute.dwMetric = pIpRoute->metric;
    ipRoute.dwTableId = pIpRoute->table;

    dwError = netmgr_client_add_static_ip_route_w(
                  hHandle,
                  &ipRoute);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(ipRoute.pwszInterfaceName);
    PMDFreeMemory(ipRoute.pwszDestNetwork);
    PMDFreeMemory(ipRoute.pwszSourceNetwork);
    PMDFreeMemory(ipRoute.pwszGateway);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_static_ip_route_w(
    PPMDHANDLE hHandle,
    NET_RPC_IP_ROUTE *pIpRoute
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pIpRoute)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_delete_static_ip_route(
                   hHandle->hRpc,
                   pIpRoute),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_delete_static_ip_route(
                   hHandle->hRpc,
                   pIpRoute),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_static_ip_route(
    PPMDHANDLE hHandle,
    NET_IP_ROUTE *pIpRoute
    )
{
    uint32_t dwError = 0;
    NET_RPC_IP_ROUTE ipRoute = {0};

    if(!hHandle || !pIpRoute)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pIpRoute->pszInterfaceName,
                                      &ipRoute.pwszInterfaceName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pIpRoute->pszDestNetwork,
                                      &ipRoute.pwszDestNetwork);
    BAIL_ON_PMD_ERROR(dwError);

    if (pIpRoute->pszGateway)
    {
        dwError = PMDAllocateStringWFromA(pIpRoute->pszGateway,
                                          &ipRoute.pwszGateway);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pIpRoute->pszSourceNetwork)
    {
        dwError = PMDAllocateStringWFromA(pIpRoute->pszSourceNetwork,
                                          &ipRoute.pwszSourceNetwork);
        BAIL_ON_PMD_ERROR(dwError);
    }

    ipRoute.scope = (NET_RPC_ROUTE_SCOPE)pIpRoute->scope;
    ipRoute.dwMetric = pIpRoute->metric;
    ipRoute.dwTableId = pIpRoute->table;

    dwError = netmgr_client_delete_static_ip_route_w(
                  hHandle,
                  &ipRoute);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(ipRoute.pwszInterfaceName);
    PMDFreeMemory(ipRoute.pwszDestNetwork);
    PMDFreeMemory(ipRoute.pwszSourceNetwork);
    PMDFreeMemory(ipRoute.pwszGateway);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_static_ip_routes_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    PNET_RPC_IP_ROUTE_ARRAY *ppIpRouteArray
)
{
    uint32_t dwError = 0;
    PNET_RPC_IP_ROUTE_ARRAY pIpRouteArray = NULL;

    if(!hHandle || !ppIpRouteArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_static_ip_routes(
                   hHandle->hRpc,
                   pwszIfname,
                   &pIpRouteArray),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_static_ip_routes(
                   hHandle->hRpc,
                   pwszIfname,
                   &pIpRouteArray),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    if(!pIpRouteArray || !pIpRouteArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppIpRouteArray = pIpRouteArray;

cleanup:
    return dwError;

error:
    if(ppIpRouteArray)
    {
        *ppIpRouteArray = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_static_ip_routes(
    PPMDHANDLE hHandle,
    char *pszIfname,
    size_t *pCount,
    NET_IP_ROUTE ***pppRouteList
)
{
    uint32_t dwError = 0;
    size_t i;
    wstring_t pwszIfname = NULL;
    NET_IP_ROUTE **ppRouteList = NULL;
    PNET_RPC_IP_ROUTE_ARRAY pIpRouteArray = NULL;

    if(!hHandle || !pCount || !pppRouteList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_static_ip_routes_w(
                  hHandle,
                  pwszIfname,
                  &pIpRouteArray);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pIpRouteArray || !pIpRouteArray->dwCount)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(pIpRouteArray->dwCount * sizeof(PNET_IP_ROUTE),
                                (void **)&ppRouteList);
    BAIL_ON_PMD_ERROR(dwError);

    for (i = 0; i < pIpRouteArray->dwCount; i++)
    {
        dwError = PMDAllocateMemory(sizeof(NET_IP_ROUTE),
                                    (void **)&ppRouteList[i]);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateStringAFromW(
                             pIpRouteArray->pRpcIpRoute[i].pwszInterfaceName,
                             &((ppRouteList[i])->pszInterfaceName));
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDAllocateStringAFromW(
                             pIpRouteArray->pRpcIpRoute[i].pwszDestNetwork,
                             &((ppRouteList[i])->pszDestNetwork));
        BAIL_ON_PMD_ERROR(dwError);
        dwError = PMDAllocateStringAFromW(
                             pIpRouteArray->pRpcIpRoute[i].pwszGateway,
                             &((ppRouteList[i])->pszGateway));
        BAIL_ON_PMD_ERROR(dwError);
        if (pIpRouteArray->pRpcIpRoute[i].pwszSourceNetwork)
        {
            dwError = PMDAllocateStringAFromW(
                             pIpRouteArray->pRpcIpRoute[i].pwszSourceNetwork,
                             &((ppRouteList[i])->pszSourceNetwork));
            BAIL_ON_PMD_ERROR(dwError);
        }
        ppRouteList[i]->scope = (NET_ROUTE_SCOPE)
                                     pIpRouteArray->pRpcIpRoute[i].scope;
        ppRouteList[i]->metric = pIpRouteArray->pRpcIpRoute[i].dwMetric;
        ppRouteList[i]->table = pIpRouteArray->pRpcIpRoute[i].dwTableId;
    }

    *pCount = pIpRouteArray->dwCount;
    *pppRouteList = ppRouteList;

cleanup:
    if (pIpRouteArray && pIpRouteArray->pRpcIpRoute)
    {
        for (i = 0; i < pIpRouteArray->dwCount; i++)
        {
            PMDRpcClientFreeMemory(
                        pIpRouteArray->pRpcIpRoute[i].pwszInterfaceName);
            PMDRpcClientFreeMemory(
                        pIpRouteArray->pRpcIpRoute[i].pwszDestNetwork);
            PMDRpcClientFreeMemory(
                        pIpRouteArray->pRpcIpRoute[i].pwszSourceNetwork);
            PMDRpcClientFreeMemory(
                        pIpRouteArray->pRpcIpRoute[i].pwszGateway);
        }
        PMDRpcClientFreeMemory(pIpRouteArray->pRpcIpRoute);
    }
    PMDRpcClientFreeMemory(pIpRouteArray);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (ppRouteList)
    {
        for (i = 0; i < pIpRouteArray->dwCount; i++)
        {
            if (ppRouteList[i] == NULL)
            {
                continue;
            }
            PMDFreeMemory(ppRouteList[i]->pszInterfaceName);
            PMDFreeMemory(ppRouteList[i]->pszDestNetwork);
            PMDFreeMemory(ppRouteList[i]->pszSourceNetwork);
            PMDFreeMemory(ppRouteList[i]->pszGateway);
            PMDFreeMemory(ppRouteList[i]);
        }
        PMDFreeMemory(ppRouteList);
    }
    goto cleanup;
}

uint32_t
netmgr_client_set_dns_servers_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_DNS_MODE mode,
    PPMD_WSTRING_ARRAY pwszDnsServers
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszDnsServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_dns_servers(
                   hHandle->hRpc,
                   pwszIfname,
                   (NET_RPC_DNS_MODE)mode,
                   pwszDnsServers),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_dns_servers(
                   hHandle->hRpc,
                   pwszIfname,
                   (NET_RPC_DNS_MODE)mode,
                   pwszDnsServers),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_dns_servers(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_DNS_MODE mode,
    size_t count,
    char **ppszDnsServers
    )
{
    uint32_t dwError = 0;
    size_t i;
    wstring_t pwszIfname = NULL;
    PPMD_WSTRING_ARRAY pwszDnsServers = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (ppszDnsServers != NULL && count)
    {
        dwError = PMDAllocateMemory(sizeof(wstring_t) * count,
                                    (void **)&pwszDnsServers->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < count; ++i)
        {
            dwError = PMDAllocateStringWFromA(ppszDnsServers[i],
                                              &pwszDnsServers->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pwszDnsServers->dwCount = count;
    }

    dwError = netmgr_client_set_dns_servers_w(
                  hHandle,
                  pwszIfname,
                  (NET_RPC_DNS_MODE)mode,
                  pwszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pwszDnsServers && pwszDnsServers->ppwszStrings)
    {
        for (i = 0; i < count; ++i)
        {
            PMDFreeMemory(pwszDnsServers->ppwszStrings[i]);
        }
        PMDFreeMemory(pwszDnsServers->ppwszStrings);
    }
    PMDFreeMemory(pwszDnsServers);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_dns_server_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsServer
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszDnsServer)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_add_dns_server(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsServer),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_add_dns_server(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsServer),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_dns_server(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszDnsServer
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszDnsServer = NULL;

    if(!hHandle || IsNullOrEmptyString(pszDnsServer))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszDnsServer, &pwszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_dns_server_w(
                  hHandle,
                  pwszIfname,
                  pwszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszDnsServer);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_dns_server_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsServer
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszDnsServer)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_delete_dns_server(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsServer),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_delete_dns_server(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsServer),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_dns_server(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszDnsServer
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszDnsServer = NULL;

    if(!hHandle || IsNullOrEmptyString(pszDnsServer))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszDnsServer, &pwszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_dns_server_w(
                  hHandle,
                  pwszIfname,
                  pwszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszDnsServer);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_dns_servers_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    NET_RPC_DNS_MODE *pMode,
    PPMD_WSTRING_ARRAY *ppwszDnsServers
    )
{
    uint32_t dwError = 0;
    NET_RPC_DNS_MODE dwMode = RPC_DNS_MODE_UNKNOWN;
    PPMD_WSTRING_ARRAY pwszDnsServers = NULL;

    if(!hHandle || !pMode || !ppwszDnsServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_dns_servers(
                   hHandle->hRpc,
                   pwszIfname,
                   &dwMode,
                   &pwszDnsServers),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_dns_servers(
                   hHandle->hRpc,
                   pwszIfname,
                   &dwMode,
                   &pwszDnsServers),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pMode = dwMode;
    *ppwszDnsServers = pwszDnsServers;

cleanup:
    return dwError;

error:
    if (pMode)
    {
        *pMode = RPC_DNS_MODE_UNKNOWN;
    }
    if (ppwszDnsServers)
    {
        *ppwszDnsServers = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_dns_servers(
    PPMDHANDLE hHandle,
    char *pszIfname,
    NET_DNS_MODE *pMode,
    size_t *pCount,
    char ***pppszDnsServers
    )
{
    uint32_t dwError = 0;
    size_t i;
    wstring_t pwszIfname = NULL;
    NET_RPC_DNS_MODE dwMode = RPC_DNS_MODE_UNKNOWN;
    PPMD_WSTRING_ARRAY pwszDnsServers = NULL;
    char **ppszDnsServers = NULL;

    if(!hHandle || !pMode || !pCount || !pppszDnsServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_dns_servers_w(
                  hHandle,
                  pwszIfname,
                  &dwMode,
                  &pwszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszDnsServers && pwszDnsServers->dwCount)
    {
        dwError = PMDAllocateMemory(sizeof(char *) * pwszDnsServers->dwCount,
                                    (void **)&ppszDnsServers);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszDnsServers->dwCount; i++)
        {
            dwError = PMDAllocateStringAFromW(pwszDnsServers->ppwszStrings[i],
                                              &ppszDnsServers[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *pMode = (NET_DNS_MODE)dwMode;
    *pCount = (pwszDnsServers != NULL) ? pwszDnsServers->dwCount : 0;
    *pppszDnsServers = ppszDnsServers;

cleanup:
    if (pwszDnsServers && pwszDnsServers->ppwszStrings)
    {
        for (i = 0; i < pwszDnsServers->dwCount; ++i)
        {
            PMDRpcClientFreeMemory(pwszDnsServers->ppwszStrings[i]);
        }
        PMDRpcClientFreeMemory(pwszDnsServers->ppwszStrings);
    }
    PMDRpcClientFreeMemory(pwszDnsServers);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (pMode)
    {
        *pMode = DNS_MODE_UNKNOWN;
    }
    if (pCount)
    {
        *pCount = 0;
    }
    if (pppszDnsServers)
    {
        *pppszDnsServers = NULL;
    }
    if (pwszDnsServers && ppszDnsServers)
    {
        for (i = 0; i < pwszDnsServers->dwCount; ++i)
        {
            PMDFreeMemory(ppszDnsServers[i]);
        }
        PMDFreeMemory(ppszDnsServers);
    }
    goto cleanup;
}

uint32_t
netmgr_client_set_dns_domains_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    PPMD_WSTRING_ARRAY pwszDnsDomains
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszDnsDomains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_dns_domains(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsDomains),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_dns_domains(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsDomains),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_dns_domains(
    PPMDHANDLE hHandle,
    char *pszIfname,
    size_t count,
    char **ppszDnsDomains
    )
{
    uint32_t dwError = 0;
    size_t i;
    wstring_t pwszIfname = NULL;
    PPMD_WSTRING_ARRAY pwszDnsDomains = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    if (ppszDnsDomains != NULL && count)
    {
        dwError = PMDAllocateMemory(sizeof(wstring_t) * count,
                                    (void **)&pwszDnsDomains->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < count; ++i)
        {
            dwError = PMDAllocateStringWFromA(ppszDnsDomains[i],
                                              &pwszDnsDomains->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pwszDnsDomains->dwCount = count;
    }

    dwError = netmgr_client_set_dns_domains_w(
                  hHandle,
                  pwszIfname,
                  pwszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pwszDnsDomains && pwszDnsDomains->ppwszStrings)
    {
        for (i = 0; i < count; ++i)
        {
            PMDFreeMemory(pwszDnsDomains->ppwszStrings[i]);
        }
        PMDFreeMemory(pwszDnsDomains->ppwszStrings);
    }
    PMDFreeMemory(pwszDnsDomains);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_dns_domains_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    PPMD_WSTRING_ARRAY *ppwszDnsDomains
    )
{
    uint32_t dwError = 0;
    PPMD_WSTRING_ARRAY pwszDnsDomains = NULL;

    if(!hHandle || !ppwszDnsDomains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_dns_domains(
                   hHandle->hRpc,
                   pwszIfname,
                   &pwszDnsDomains),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_dns_domains(
                   hHandle->hRpc,
                   pwszIfname,
                   &pwszDnsDomains),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszDnsDomains = pwszDnsDomains;

cleanup:
    return dwError;

error:
    if (ppwszDnsDomains)
    {
        *ppwszDnsDomains = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_dns_domains(
    PPMDHANDLE hHandle,
    char *pszIfname,
    size_t *pCount,
    char ***pppszDnsDomains
    )
{
    uint32_t dwError = 0;
    size_t i;
    PPMD_WSTRING_ARRAY pwszDnsDomains = NULL;
    wstring_t pwszIfname = NULL;
    char **ppszDnsDomains = NULL;

    if(!hHandle || !pCount || !pppszDnsDomains)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_dns_domains_w(
                  hHandle,
                  pwszIfname,
                  &pwszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszDnsDomains && pwszDnsDomains->dwCount)
    {
        dwError = PMDAllocateMemory(sizeof(char *) * pwszDnsDomains->dwCount,
                                    (void **)&ppszDnsDomains);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < pwszDnsDomains->dwCount; i++)
        {
            dwError = PMDAllocateStringAFromW(pwszDnsDomains->ppwszStrings[i],
                                              &ppszDnsDomains[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *pCount = (pwszDnsDomains != NULL) ? pwszDnsDomains->dwCount : 0;
    *pppszDnsDomains = ppszDnsDomains;

cleanup:
    if (pwszDnsDomains && pwszDnsDomains->ppwszStrings)
    {
        for (i = 0; i < pwszDnsDomains->dwCount; ++i)
        {
            PMDRpcClientFreeMemory(pwszDnsDomains->ppwszStrings[i]);
        }
        PMDRpcClientFreeMemory(pwszDnsDomains->ppwszStrings);
    }
    PMDRpcClientFreeMemory(pwszDnsDomains);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if (pCount)
    {
        *pCount = 0;
    }
    if (pppszDnsDomains)
    {
        *pppszDnsDomains = NULL;
    }
    if (pwszDnsDomains && ppszDnsDomains)
    {
        for (i = 0; i < pwszDnsDomains->dwCount; ++i)
        {
            PMDFreeMemory(ppszDnsDomains[i]);
        }
        PMDFreeMemory(ppszDnsDomains);
    }
    goto cleanup;
}

uint32_t
netmgr_client_add_dns_domain_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsDomain
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszDnsDomain)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_add_dns_domain(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsDomain),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_add_dns_domain(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsDomain),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_dns_domain(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszDnsDomain
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszDnsDomain = NULL;

    if(!hHandle || IsNullOrEmptyString(pszDnsDomain))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = PMDAllocateStringWFromA(pszDnsDomain, &pwszDnsDomain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_dns_domain_w(
                  hHandle,
                  pwszIfname,
                  pwszDnsDomain);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszDnsDomain);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_dns_domain_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDnsDomain
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszDnsDomain)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_delete_dns_domain(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsDomain),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_delete_dns_domain(
                   hHandle->hRpc,
                   pwszIfname,
                   pwszDnsDomain),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_dns_domain(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char *pszDnsDomain
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszDnsDomain = NULL;

    if(!hHandle || IsNullOrEmptyString(pszDnsDomain))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszDnsDomain, &pwszDnsDomain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_dns_domain_w(
                  hHandle,
                  pwszIfname,
                  pwszDnsDomain);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszDnsDomain);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_iaid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t *pdwIaid
    )
{
    uint32_t dwError = 0;
    uint32_t dwIaid = 0;

    if(!hHandle || !pwszIfname || !pdwIaid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_iaid(hHandle->hRpc, pwszIfname, &dwIaid),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_iaid(hHandle->hRpc, pwszIfname, &dwIaid), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pdwIaid = dwIaid;

cleanup:
    return dwError;

error:
    if(pdwIaid)
    {
        *pdwIaid = 0;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_iaid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t *pdwIaid
    )
{
    uint32_t dwError = 0;
    uint32_t dwIaid = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname) || !pdwIaid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_iaid_w(hHandle, pwszIfname, &dwIaid);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwIaid = dwIaid;

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if(pdwIaid)
    {
        *pdwIaid = 0;
    }
    goto cleanup;
}

uint32_t
netmgr_client_set_iaid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    uint32_t dwIaid
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_iaid(hHandle->hRpc, pwszIfname, dwIaid),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_iaid(hHandle->hRpc, pwszIfname, dwIaid), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_iaid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    uint32_t dwIaid
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszIfname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_iaid_w(hHandle, pwszIfname, dwIaid);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_duid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t *ppwszDuid
    )
{
    uint32_t dwError = 0;
    wstring_t pwszDuid = NULL;

    if(!hHandle || !ppwszDuid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_duid(hHandle->hRpc, pwszIfname, &pwszDuid),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_duid(hHandle->hRpc, pwszIfname, &pwszDuid),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszDuid = pwszDuid;

cleanup:
    return dwError;

error:
    if(ppwszDuid)
    {
        *ppwszDuid = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_duid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char** ppszDuid
    )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszDuid = NULL;
    char* pszDuid = NULL;

    if(!hHandle || !ppszDuid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_duid_w(hHandle, pwszIfname, &pwszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszDuid, &pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszDuid = pszDuid;

cleanup:
    PMDRpcClientFreeMemory(pwszDuid);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    if(ppszDuid)
    {
        *ppszDuid = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszDuid);
    goto cleanup;
}

uint32_t
netmgr_client_set_duid_w(
    PPMDHANDLE hHandle,
    wstring_t pwszIfname,
    wstring_t pwszDuid
   )
{
    uint32_t dwError = 0;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_duid(hHandle->hRpc, pwszIfname, pwszDuid),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_duid(hHandle->hRpc, pwszIfname, pwszDuid),
                   dwError);
    }

    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_duid(
    PPMDHANDLE hHandle,
    char *pszIfname,
    char* pszDuid
   )
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;
    wstring_t pwszDuid = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszIfname)
    {
        dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pszDuid)
    {
        dwError = PMDAllocateStringWFromA(pszDuid, &pwszDuid);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_duid_w(hHandle, pwszIfname, pwszDuid);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszDuid);
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_ntp_servers(
                   hHandle->hRpc,
                   pwszNtpServers),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_ntp_servers(
                   hHandle->hRpc,
                   pwszNtpServers),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_set_ntp_servers(
    PPMDHANDLE hHandle,
    size_t nCount,
    char **ppszNtpServers
    )
{
    uint32_t dwError = 0;
    size_t i = 0;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;

    if(!hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (ppszNtpServers != NULL && nCount)
    {
        dwError = PMDAllocateMemory(sizeof(wstring_t) * nCount,
                                    (void **)&pwszNtpServers->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; ++i)
        {
            dwError = PMDAllocateStringWFromA(
                          ppszNtpServers[i],
                          &pwszNtpServers->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pwszNtpServers->dwCount = nCount;
    }

    dwError = netmgr_client_set_ntp_servers_w(
                  hHandle,
                  pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pwszNtpServers && pwszNtpServers->ppwszStrings)
    {
        for (i = 0; i < nCount; ++i)
        {
            PMDFreeMemory(pwszNtpServers->ppwszStrings[i]);
        }
        PMDFreeMemory(pwszNtpServers->ppwszStrings);
    }
    PMDFreeMemory(pwszNtpServers);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_add_ntp_servers(
                   hHandle->hRpc,
                   pwszNtpServers),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_add_ntp_servers(
                   hHandle->hRpc,
                   pwszNtpServers),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_add_ntp_servers(
    PPMDHANDLE hHandle,
    size_t nCount,
    const char **ppszNtpServers)
{
    uint32_t dwError = 0;
    size_t i = 0;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;

    if(!hHandle || nCount == 0 || !ppszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (ppszNtpServers != NULL && nCount)
    {
        dwError = PMDAllocateMemory(sizeof(wstring_t) * nCount,
                                    (void **)&pwszNtpServers->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; ++i)
        {
            dwError = PMDAllocateStringWFromA(
                          ppszNtpServers[i],
                          &pwszNtpServers->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pwszNtpServers->dwCount = nCount;
    }

    dwError = netmgr_client_add_ntp_servers_w(
                  hHandle,
                  pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pwszNtpServers && pwszNtpServers->ppwszStrings)
    {
        for (i = 0; i < nCount; ++i)
        {
            PMDFreeMemory(pwszNtpServers->ppwszStrings[i]);
        }
        PMDFreeMemory(pwszNtpServers->ppwszStrings);
    }
    PMDFreeMemory(pwszNtpServers);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY pwszNtpServers
    )
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_delete_ntp_servers(
                   hHandle->hRpc,
                   pwszNtpServers),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_delete_ntp_servers(
                   hHandle->hRpc,
                   pwszNtpServers),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_delete_ntp_servers(
    PPMDHANDLE hHandle,
    size_t nCount,
    const char **ppszNtpServers)
{
    uint32_t dwError = 0;
    size_t i = 0;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;

    if(!hHandle || nCount == 0 || !ppszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_WSTRING_ARRAY),
                                (void **)&pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (ppszNtpServers != NULL && nCount)
    {
        dwError = PMDAllocateMemory(sizeof(wstring_t) * nCount,
                                    (void **)&pwszNtpServers->ppwszStrings);
        BAIL_ON_PMD_ERROR(dwError);

        for (i = 0; i < nCount; ++i)
        {
            dwError = PMDAllocateStringWFromA(
                          ppszNtpServers[i],
                          &pwszNtpServers->ppwszStrings[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
        pwszNtpServers->dwCount = nCount;
    }

    dwError = netmgr_client_delete_ntp_servers_w(
                  hHandle,
                  pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pwszNtpServers && pwszNtpServers->ppwszStrings)
    {
        for (i = 0; i < nCount; ++i)
        {
            PMDFreeMemory(pwszNtpServers->ppwszStrings[i]);
        }
        PMDFreeMemory(pwszNtpServers->ppwszStrings);
    }
    PMDFreeMemory(pwszNtpServers);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_ntp_servers_w(
    PPMDHANDLE hHandle,
    PPMD_WSTRING_ARRAY *ppwszNtpServers
    )
{
    uint32_t dwError = 0;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;

    if(!hHandle || !ppwszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_ntp_servers(
                   hHandle->hRpc,
                   &pwszNtpServers),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_ntp_servers(
                   hHandle->hRpc,
                   &pwszNtpServers),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszNtpServers = pwszNtpServers;

cleanup:
    return dwError;

error:
    if (ppwszNtpServers)
    {
        *ppwszNtpServers = NULL;
    }
    goto cleanup;
}

uint32_t
netmgr_client_get_ntp_servers(
    PPMDHANDLE hHandle,
    size_t *pnCount,
    char ***pppszNtpServers
    )
{
    uint32_t dwError = 0;
    PPMD_WSTRING_ARRAY pwszNtpServers = NULL;
    char **ppszNtpServers = NULL;

    if(!hHandle || !pnCount || !pppszNtpServers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_ntp_servers_w(
                  hHandle,
                  &pwszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (pwszNtpServers && pwszNtpServers->dwCount)
    {
        dwError = PMDAllocateMemory(sizeof(char *) * pwszNtpServers->dwCount,
                                    (void **)&ppszNtpServers);
        BAIL_ON_PMD_ERROR(dwError);

        size_t i = 0;
        for (i = 0; i < pwszNtpServers->dwCount; i++)
        {
            dwError = PMDAllocateStringAFromW(pwszNtpServers->ppwszStrings[i],
                                              &ppszNtpServers[i]);
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *pnCount = (pwszNtpServers != NULL) ? pwszNtpServers->dwCount : 0;
    *pppszNtpServers = ppszNtpServers;

cleanup:
    if (pwszNtpServers && pwszNtpServers->ppwszStrings)
    {
        size_t i = 0;
        for (i = 0; i < pwszNtpServers->dwCount; ++i)
        {
            PMDRpcClientFreeMemory(pwszNtpServers->ppwszStrings[i]);
        }
        PMDRpcClientFreeMemory(pwszNtpServers->ppwszStrings);
    }
    PMDRpcClientFreeMemory(pwszNtpServers);
    return dwError;

error:
    if (pnCount)
    {
        *pnCount = 0;
    }
    if (pppszNtpServers)
    {
        *pppszNtpServers = NULL;
    }
    if (pwszNtpServers && ppszNtpServers)
    {
        size_t i = 0;
        for (i = 0; i < pwszNtpServers->dwCount; ++i)
        {
            PMDFreeMemory(ppszNtpServers[i]);
        }
        PMDFreeMemory(ppszNtpServers);
    }
    goto cleanup;
}

uint32_t
netmgr_client_set_hostname_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszHostname
)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszHostname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_hostname(hHandle->hRpc, pwszHostname),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_hostname(hHandle->hRpc, pwszHostname), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_set_hostname(
    PPMDHANDLE hHandle,
    const char *pszHostname
)
{
    uint32_t dwError = 0;
    wstring_t pwszHostname = NULL;

    if(!hHandle || IsNullOrEmptyString(pszHostname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszHostname, &pwszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_hostname_w(hHandle, pwszHostname);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszHostname);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_get_hostname_w(
    PPMDHANDLE hHandle,
    wstring_t *ppwszHostname
)
{
    uint32_t dwError = 0;
    wstring_t pwszHostname = NULL;

    if(!hHandle || !ppwszHostname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_hostname(hHandle->hRpc, &pwszHostname),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_hostname(hHandle->hRpc, &pwszHostname), dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszHostname = pwszHostname;

cleanup:
    return dwError;

error:
    if(ppwszHostname)
    {
        *ppwszHostname = NULL;
    }
    PMDRpcClientFreeMemory(pwszHostname);
    goto cleanup;
}

uint32_t
netmgr_client_get_hostname(
    PPMDHANDLE hHandle,
    char **ppszHostname
)
{
    uint32_t dwError = 0;
    wstring_t pwszHostname = NULL;
    char* pszHostname = NULL;

    if(!hHandle || !ppszHostname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_hostname_w(hHandle, &pwszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszHostname, &pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszHostname = pszHostname;

cleanup:
    PMDRpcClientFreeMemory(pwszHostname);
    return dwError;
error:
    if(ppszHostname)
    {
        *ppszHostname = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszHostname);
    goto cleanup;
}

uint32_t
netmgr_client_wait_for_link_up_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t dwTimeout)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_wait_for_link_up(
                   hHandle->hRpc,
                   pwszIfname,
                   dwTimeout),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_wait_for_link_up(
                   hHandle->hRpc,
                   pwszIfname,
                   dwTimeout),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_wait_for_link_up(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    uint32_t dwTimeout)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || !pszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_wait_for_link_up_w(
                  hHandle,
                  pwszIfname,
                  dwTimeout);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_wait_for_ip_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszIfname,
    uint32_t dwTimeout,
    NET_ADDR_TYPE dwAddrTypes)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_wait_for_ip(
                   hHandle->hRpc,
                   pwszIfname,
                   dwTimeout,
                   dwAddrTypes),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_wait_for_ip(
                   hHandle->hRpc,
                   pwszIfname,
                   dwTimeout,
                   dwAddrTypes),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_wait_for_ip(
    PPMDHANDLE hHandle,
    const char *pszIfname,
    uint32_t dwTimeout,
    NET_ADDR_TYPE dwAddrTypes)
{
    uint32_t dwError = 0;
    wstring_t pwszIfname = NULL;

    if(!hHandle || !pszIfname)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszIfname, &pwszIfname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_wait_for_ip_w(
                  hHandle,
                  pwszIfname,
                  dwTimeout,
                  dwAddrTypes);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszIfname);
    return dwError;

error:
    goto cleanup;
}

uint32_t
netmgr_client_get_error_info_w(
    PPMDHANDLE hHandle,
    uint32_t nmErrCode,
    wstring_t *ppwszErrInfo
    )
{
    uint32_t dwError = 0;
    wstring_t pwszErrInfo = NULL;

    if(!hHandle || !ppwszErrInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_error_info(
                   hHandle->hRpc,
                   nmErrCode,
                   &pwszErrInfo),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_error_info(
                   hHandle->hRpc,
                   nmErrCode,
                   &pwszErrInfo),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszErrInfo = pwszErrInfo;

cleanup:
    return dwError;
error:
    if(ppwszErrInfo)
    {
        *ppwszErrInfo = NULL;
    }
    PMDRpcClientFreeMemory(pwszErrInfo);
    goto cleanup;
}

uint32_t
netmgr_client_get_error_info(
    PPMDHANDLE hHandle,
    uint32_t nmErrCode,
    char **ppszErrInfo)
{
    uint32_t dwError = 0;
    wstring_t pwszErrInfo = NULL;
    char* pszErrInfo = NULL;

    if(!hHandle || !ppszErrInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_error_info_w(
                  hHandle,
                  nmErrCode,
                  &pwszErrInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringAFromW(pwszErrInfo, &pszErrInfo);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszErrInfo = pszErrInfo;

cleanup:
    PMDRpcClientFreeMemory(pwszErrInfo);
    return dwError;
error:
    if(ppszErrInfo)
    {
        *ppszErrInfo = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszErrInfo);
    goto cleanup;
}

uint32_t
netmgr_client_set_network_param_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszObjectName,
    const wstring_t pwszParamName,
    const wstring_t pwszParamValue)
{
    uint32_t dwError = 0;

    if(!hHandle || !pwszObjectName || !pwszParamName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_set_network_param(
                   hHandle->hRpc,
                   pwszObjectName,
                   pwszParamName,
                   pwszParamValue),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_set_network_param(
                   hHandle->hRpc,
                   pwszObjectName,
                   pwszParamName,
                   pwszParamValue),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_set_network_param(
    PPMDHANDLE hHandle,
    const char *pszObjectName,
    const char *pszParamName,
    const char *pszParamValue)
{
    uint32_t dwError = 0;
    wstring_t pwszObjectName = NULL;
    wstring_t pwszParamName = NULL;
    wstring_t pwszParamValue = NULL;

    if(!hHandle || !pszObjectName || !pszParamName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszObjectName, &pwszObjectName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszParamName, &pwszParamName);
    BAIL_ON_PMD_ERROR(dwError);

    if(pszParamValue)
    {
        dwError = PMDAllocateStringWFromA(pszParamValue, &pwszParamValue);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_network_param_w(
                  hHandle,
                  pwszObjectName,
                  pwszParamName,
                  pwszParamValue);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pwszParamValue);
    PMDFreeMemory(pwszParamName);
    PMDFreeMemory(pwszObjectName);
    return dwError;
error:
    goto cleanup;
}

uint32_t
netmgr_client_get_network_param_w(
    PPMDHANDLE hHandle,
    const wstring_t pwszObjectName,
    const wstring_t pwszParamName,
    wstring_t *ppwszParamValue)
{
    uint32_t dwError = 0;
    wstring_t pwszParamValue = NULL;

    if(!hHandle || !pwszObjectName || !pwszParamName || !ppwszParamValue)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(hHandle->nPrivSep)
    {
        DO_RPC(netmgr_privsep_rpc_get_network_param(
                   hHandle->hRpc,
                   pwszObjectName,
                   pwszParamName,
                   &pwszParamValue),
                   dwError);
    }
    else
    {
        DO_RPC(netmgr_rpc_get_network_param(
                   hHandle->hRpc,
                   pwszObjectName,
                   pwszParamName,
                   &pwszParamValue),
                   dwError);
    }
    BAIL_ON_PMD_ERROR(dwError);

    *ppwszParamValue = pwszParamValue;

cleanup:
    return dwError;
error:
    if (ppwszParamValue)
    {
        *ppwszParamValue = NULL;
    }
    PMDRpcClientFreeMemory(pwszParamValue);
    goto cleanup;
}

uint32_t
netmgr_client_get_network_param(
    PPMDHANDLE hHandle,
    const char *pszObjectName,
    const char *pszParamName,
    char **ppszParamValue)
{
    uint32_t dwError = 0;
    wstring_t pwszObjectName = NULL;
    wstring_t pwszParamName = NULL;
    wstring_t pwszParamValue = NULL;
    char *pszParamValue = NULL;

    if(!hHandle || !pszObjectName || !pszParamName || !ppszParamValue)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringWFromA(pszObjectName, &pwszObjectName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringWFromA(pszParamName, &pwszParamName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_network_param_w(
                  hHandle,
                  pwszObjectName,
                  pwszParamName,
                  &pwszParamValue);
    BAIL_ON_PMD_ERROR(dwError);

    if(pwszParamValue)
    {
        dwError = PMDAllocateStringAFromW(pwszParamValue, &pszParamValue);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszParamValue = pszParamValue;

cleanup:
    PMDFreeMemory(pwszParamValue);
    PMDFreeMemory(pwszParamName);
    PMDFreeMemory(pwszObjectName);
    return dwError;
error:
    if (ppszParamValue)
    {
        *ppszParamValue = NULL;
    }
    goto cleanup;
}
