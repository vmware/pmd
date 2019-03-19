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

#include "includes.h"
#include <pmd_netmgr.h>

REST_MODULE _net_rest_module[] =
{
    {
        "/v1/net/dns/domains",
        {
            net_rest_get_dns_domains,
            net_rest_put_dns_domains,
            net_rest_add_dns_domain,
            net_rest_delete_dns_domain
        }
    },
    {
        "/v1/net/dns/servers",
        {
            net_rest_get_dns_servers,
            net_rest_put_dns_servers,
            net_rest_add_dns_server,
            net_rest_delete_dns_server
        }
    },
    {
        "/v1/net/dhcp/duid",
        {net_rest_get_dhcp_duid, net_rest_put_dhcp_duid, NULL, NULL}
    },
    {
        "/v1/net/dhcp/iaid",
        {net_rest_get_dhcp_iaid, net_rest_put_dhcp_iaid, NULL, NULL}
    },
    {
        "/v1/net/ifdown",
        {NULL, NULL, net_rest_ifdown, NULL}
    },
    {
        "/v1/net/ifup",
        {NULL, NULL, net_rest_ifup, NULL}
    },
    {
        "/v1/net/ip/addr",
        {net_rest_get_ip_addr, NULL, NULL, NULL}
    },
    {
        "/v1/net/ip/route",
        {
         net_rest_get_static_ip_route,
         net_rest_put_static_ip_route,
         NULL,
         net_rest_delete_static_ip_route
        }
    },
    {
        "/v1/net/ipv4/gateway",
        {net_rest_get_ipv4_gateway, net_rest_put_ipv4_gateway, NULL, NULL}
    },
    {
        "/v1/net/ipv6/addr",
        {
         NULL,
         net_rest_put_static_ipv6_addr,
         NULL,
         net_rest_delete_static_ipv6_addr
        }
    },
    {
        "/v1/net/ipv6/gateway",
        {net_rest_get_ipv6_gateway, net_rest_put_ipv6_gateway, NULL, NULL}
    },
    {
        "/v1/net/ipv6/addr/mode",
        {net_rest_get_ipv6_addr_mode, net_rest_put_ipv6_addr_mode, NULL, NULL}
    },
    {
        "/v1/net/link/info",
        {net_rest_get_link_info, NULL, NULL, NULL}
    },
    {
        "/v1/net/link/mode",
        {net_rest_get_link_mode, net_rest_put_link_mode, NULL, NULL}
    },
    {
        "/v1/net/link/mtu",
        {net_rest_get_link_mtu, net_rest_put_link_mtu, NULL, NULL}
    },
    {
        "/v1/net/link/state",
        {net_rest_get_link_state, net_rest_put_link_state, NULL, NULL}
    },
    {
        "/v1/net/mac_addr",
        {net_rest_get_mac_addr, net_rest_put_mac_addr, NULL, NULL}
    },
    {
        "/v1/net/ntp/servers",
        {
            net_rest_get_ntp_servers,
            net_rest_put_ntp_servers,
            NULL,
            net_rest_delete_ntp_servers
        }
    },
    {
        "/v1/net/version",
        {net_rest_get_version, NULL, NULL, NULL}
    },
    {
        "/v1/net/hostname",
        {net_rest_get_hostname, net_rest_set_hostname, NULL, NULL}
    },
    {
        "/v1/net/waitforlink",
        {NULL, NULL, net_rest_waitforlink, NULL}
    },
    {
        "/v1/net/waitforip",
        {NULL, NULL, net_rest_waitforip, NULL}
    },
    {0}
};

uint32_t
net_rest_get_registration(
    PREST_MODULE *ppRestModule
    )
{
    uint32_t dwError = 0;

    if(!ppRestModule)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppRestModule = _net_rest_module;

cleanup:
    return dwError;

error:
    goto cleanup;
}

uint32_t
net_open_privsep_rest(
    PREST_AUTH pRestAuth,
    PPMDHANDLE *phPMD
    )
{
    uint32_t dwError = 0;
    PPMDHANDLE hPMD = NULL;
    char *pszUser = NULL;
    char *pszPass = NULL;

    if(!pRestAuth || !phPMD)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pRestAuth->nAuthMethod != REST_AUTH_BASIC)
    {
        dwError = ERROR_INVALID_REST_AUTH;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = base64_get_user_pass(
                  pRestAuth->pszAuthBase64,
                  &pszUser,
                  &pszPass);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = rpc_open_privsep(
                  NET_PRIVSEP,
                  pszUser,
                  pszPass,
                  NULL,
                  &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    *phPMD = hPMD;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszUser);
    PMD_SAFE_FREE_MEMORY(pszPass);
    return dwError;

error:
    rpc_free_handle(hPMD);
    goto cleanup;
}

static uint32_t
net_str_to_dns_mode(
    char *pszMode,
    NET_DNS_MODE *pMode
    )
{
    uint32_t dwError = 0;
    NET_DNS_MODE nMode = DNS_MODE_INVALID;

    if (!pMode)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!strcmp(pszMode, "static"))
    {
        nMode = STATIC_DNS;
    }
    else if (!strcmp(pszMode, "dhcp"))
    {
        nMode = DHCP_DNS;
    }
    else
    {
        nMode = DNS_MODE_INVALID;
    }

    *pMode = nMode;

cleanup:
    return dwError;

error:
    goto cleanup;
}

static uint32_t
net_dns_mode_to_str(
    NET_DNS_MODE nMode,
    char **ppszMode
    )
{
    uint32_t dwError = 0;
    char *pszMode = NULL;

    switch(nMode)
    {
        case STATIC_DNS:
            dwError = PMDAllocateString("static", &pszMode);
            BAIL_ON_PMD_ERROR(dwError);
        break;
        case DHCP_DNS:
            dwError = PMDAllocateString("dhcp", &pszMode);
            BAIL_ON_PMD_ERROR(dwError);
        break;
        default:
            dwError = EINVAL;
            BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszMode = pszMode;

cleanup:
    return dwError;

error:
   PMD_SAFE_FREE_MEMORY(pszMode);
   goto cleanup;
}

void
netmgmt_free_ip_addrs(
    PNET_IP_ADDR *ppIpAddrArray,
    size_t dwCount
    )
{
    size_t i = 0;
    if(!dwCount || !ppIpAddrArray)
    {
        return;
    }
    for (i = 0; i < dwCount; i++)
    {
        if (ppIpAddrArray[i] == NULL)
        {
            continue;
        }
        PMDFreeMemory(ppIpAddrArray[i]->pszInterfaceName);
        PMDFreeMemory(ppIpAddrArray[i]->pszIPAddrPrefix);
        PMDFreeMemory(ppIpAddrArray[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppIpAddrArray);
}

void
netmgmt_free_iproutes(
    PNET_IP_ROUTE *ppRouteArray,
    size_t dwCount
    )
{
    size_t i = 0;
    if(!dwCount || !ppRouteArray)
    {
        return;
    }
    for (i = 0; i < dwCount; i++)
    {
        if (ppRouteArray[i] == NULL)
        {
            continue;
        }
        PMDFreeMemory(ppRouteArray[i]->pszInterfaceName);
        PMDFreeMemory(ppRouteArray[i]->pszDestNetwork);
        PMDFreeMemory(ppRouteArray[i]->pszSourceNetwork);
        PMDFreeMemory(ppRouteArray[i]->pszGateway);
        PMDFreeMemory(ppRouteArray[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppRouteArray);
}

uint32_t
net_rest_add_dns_server(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    int i = 0;
    int nCount = 0;
    json_t *pJson = NULL, *pRoot = NULL;
    char *pszIfName = NULL;
    char *pszOutputJson = NULL;
    char *pszDnsServer = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "server", &pszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_dns_server(
                  hPMD,
                  pszIfName,
                  pszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    PMD_SAFE_FREE_MEMORY(pszDnsServer);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson != NULL)
    {
        *ppOutputJson = NULL;
    }
    goto cleanup;
}

uint32_t
net_rest_delete_dns_server(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    int i = 0;
    int nCount = 0;
    json_t *pJson = NULL, *pRoot = NULL;
    char *pszIfName = NULL;
    char *pszOutputJson = NULL;
    char *pszDnsServer = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "server", &pszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_dns_server(
                  hPMD,
                  pszIfName,
                  pszDnsServer);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    PMD_SAFE_FREE_MEMORY(pszDnsServer);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson != NULL)
    {
        *ppOutputJson = NULL;
    }
    goto cleanup;
}

uint32_t
net_rest_put_dns_servers(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    int i = 0;
    int nCount = 0;
    json_t *pJson = NULL, *pRoot = NULL;
    NET_DNS_MODE mode;
    char *pszIfName = NULL, *pszMode = NULL;
    char *pszOutputJson = NULL;
    char **ppszDnsServers = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "mode", &pszMode);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_str_to_dns_mode(pszMode, &mode);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_array(pJson,
                                    "servers",
                                    &nCount,
                                    &ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_dns_servers(
                  hPMD,
                  pszIfName,
                  mode,
                  (size_t)nCount,
                  ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    PMDFreeStringArrayWithCount(ppszDnsServers, nCount);
    PMD_SAFE_FREE_MEMORY(pszMode);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson != NULL)
    {
        *ppOutputJson = NULL;
    }
    goto cleanup;
}

uint32_t
net_rest_get_dns_servers(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    NET_DNS_MODE mode;
    int nCount = 0;
    int i = 0;
    char **ppszDnsServers = NULL;
    json_t *pRoot = NULL;
    json_t *pServerArray = NULL;
    char *pszMode = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_dns_servers(
                  hPMD,
                  pszIfName,
                  &mode,
                  (size_t *)&nCount,
                  &ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_dns_mode_to_str(mode, &pszMode);
    BAIL_ON_PMD_ERROR(dwError);

    json_object_set_new(pRoot, "mode", json_string(pszMode));

    pServerArray = json_array();
    json_object_set_new(pRoot, "servers", pServerArray);
    for(i = 0; i < nCount; ++i)
    {
        json_array_append_new(pServerArray, json_string(ppszDnsServers[i]));
    }

    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    for(i = 0; i < nCount; ++i)
    {
        PMD_SAFE_FREE_MEMORY(ppszDnsServers[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszDnsServers);
    PMD_SAFE_FREE_MEMORY(pszMode);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_dns_domains(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char **ppszDnsDomains = NULL;
    json_t *pJson = NULL;
    json_t *pRoot = NULL;
    json_t *pServerArray = NULL;
    char *pszMode = NULL;
    size_t nCount = 0;
    size_t i = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        if(dwError == ENOENT)
        {
            dwError = 0;
        }
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_dns_domains(
                  hPMD,
                  pszIfName,
                  &nCount,
                  &ppszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pServerArray = json_array();
    json_object_set_new(pRoot, "domains", pServerArray);
    for(i = 0; i < nCount; ++i)
    {
        json_array_append_new(pServerArray, json_string(ppszDnsDomains[i]));
    }

    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    for(i = 0; i < nCount; ++i)
    {
        PMD_SAFE_FREE_MEMORY(ppszDnsDomains[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszDnsDomains);
    PMD_SAFE_FREE_MEMORY(pszIfName);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_dns_domains(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char **ppszDnsDomains = NULL;
    json_t *pJson = NULL;
    json_t *pDomainsArray = NULL;
    size_t nCount = 0;
    size_t i = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        if(dwError == ENOENT)
        {
            dwError = 0;
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_array(pJson,
                                        "domains",
                                        (int *)&nCount,
                                        &ppszDnsDomains);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_dns_domains(
                  hPMD,
                  pszIfName,
                  nCount,
                  ppszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMDFreeStringArrayWithCount(ppszDnsDomains, nCount);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_add_dns_domain(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDnsDomain = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        if(dwError == ENOENT)
        {
            dwError = 0;
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "domains", &pszDnsDomain);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_dns_domain(
                  hPMD,
                  pszIfName,
                  pszDnsDomain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDnsDomain);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_delete_dns_domain(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDnsDomain = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        if(dwError == ENOENT)
        {
            dwError = 0;
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "domains", &pszDnsDomain);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_dns_domain(
                  hPMD,
                  pszIfName,
                  pszDnsDomain);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDnsDomain);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_dhcp_duid(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDuid= NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        if(dwError == ENOENT)
        {
            dwError = 0;
        }
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_duid(hPMD, pszIfName, &pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("duid", pszDuid, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDuid);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_dhcp_duid(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDuid= NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        if(dwError == ENOENT)
        {
            dwError = 0;
        }
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "duid", &pszDuid);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_duid(hPMD, pszIfName, pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDuid);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_dhcp_iaid(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszIaid= NULL;
    json_t *pJson = NULL;
    uint32_t nIaid = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_iaid(hPMD, pszIfName, &nIaid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszIaid, "%d", nIaid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("iaid", pszIaid, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIaid);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_dhcp_iaid(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszIaid= NULL;
    json_t *pJson = NULL;
    int nIaid = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "iaid", &pszIaid);
        BAIL_ON_PMD_ERROR(dwError);
    }

    nIaid = atoi(pszIaid);
    if(nIaid == 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_iaid(hPMD, pszIfName, nIaid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIaid);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_ifdown(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_ifdown(hPMD, pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_ifup(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_ifup(hPMD, pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
get_addr_array_json_string(
    size_t dwCount,
    NET_IP_ADDR **ppAddrArray,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    size_t i = 0;

    if(dwCount == 0 || !ppAddrArray || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < dwCount; ++i)
    {
        PNET_IP_ADDR pAddr = ppAddrArray[i];
        json_t *pObj = json_object();
        json_object_set_new(pObj, "interface", json_string(pAddr->pszInterfaceName));
        json_object_set_new(pObj, "addr_type", json_integer(pAddr->type));
        json_object_set_new(pObj, "prefix", json_string(pAddr->pszIPAddrPrefix));
        json_array_append_new(pRoot, pObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
net_rest_get_ip_addr(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszAddrType = NULL;
    json_t *pJson = NULL;
    uint32_t nAddrTypes = 0;
    size_t dwCount = 0;
    PNET_IP_ADDR *ppIpAddr = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_opt_string_value(pJson, "addr_type", &pszAddrType);
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszAddrType))
    {
        nAddrTypes = atoi(pszAddrType);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ip_addr(
                  hPMD,
                  pszIfName,
                  nAddrTypes,
                  &dwCount,
                  &ppIpAddr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_addr_array_json_string(dwCount, ppIpAddr, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszAddrType);
    netmgmt_free_ip_addrs(ppIpAddr, dwCount);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
get_route_array_json_string(
    size_t dwCount,
    NET_IP_ROUTE **ppRouteArray,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    size_t i = 0;

    if(dwCount == 0 || !ppRouteArray || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < dwCount; ++i)
    {
        PNET_IP_ROUTE pRoute = ppRouteArray[i];
        json_t *pObj = json_object();
        json_object_set_new(pObj, "interface", json_string(pRoute->pszInterfaceName));
        json_object_set_new(pObj, "dest_net", json_string(pRoute->pszDestNetwork));
        json_object_set_new(pObj, "source_net", json_string(pRoute->pszSourceNetwork));
        json_object_set_new(pObj, "gateway", json_string(pRoute->pszGateway));
        json_object_set_new(pObj, "scope", json_integer(pRoute->scope));
        json_object_set_new(pObj, "metric", json_integer(pRoute->metric));
        json_object_set_new(pObj, "table", json_integer(pRoute->table));
        json_array_append_new(pRoot, pObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
net_rest_get_static_ip_route(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    PNET_IP_ROUTE *ppIpRoutes = NULL;
    size_t dwCount = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_static_ip_routes(
                  hPMD,
                  pszIfName,
                  &dwCount,
                  &ppIpRoutes);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_route_array_json_string(dwCount, ppIpRoutes, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    netmgmt_free_iproutes(ppIpRoutes, dwCount);
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_static_ip_route(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    NET_IP_ROUTE stIpRoute = {0};
    size_t dwCount = 0;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_static_ip_route(hPMD, &stIpRoute);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_delete_static_ip_route(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    NET_IP_ROUTE stIpRoute = {0};
    size_t dwCount = 0;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_static_ip_route(hPMD, &stIpRoute);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_ipv4_gateway(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszMode = NULL;
    char *pszPrefix = NULL;
    char *pszGateway= NULL;
    json_t *pJson = NULL;
    NET_IPV4_ADDR_MODE nMode = IPV4_ADDR_MODE_NONE;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv4_addr_gateway(
                  hPMD,
                  pszIfName,
                  &nMode,
                  &pszPrefix,
                  &pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    if(nMode == IPV4_ADDR_MODE_NONE)
    {
        pszMode = "none";
    }
    else if(nMode == IPV4_ADDR_MODE_DHCP)
    {
        pszMode = "dhcp";
    }
    else if(nMode == IPV4_ADDR_MODE_STATIC)
    {
        pszMode = "static";
    }

    dwError = json_string_from_key_value("mode", pszMode, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszPrefix);
    PMD_SAFE_FREE_MEMORY(pszGateway);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_ipv4_gateway(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszMode = NULL;
    char *pszPrefix = NULL;
    char *pszGateway= NULL;
    json_t *pJson = NULL;
    NET_IPV4_ADDR_MODE nMode = IPV4_ADDR_MODE_NONE;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "mode", &pszMode);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "prefix", &pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "gateway", &pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    if(!strcasecmp(pszMode, "static"))
    {
        nMode = IPV4_ADDR_MODE_STATIC;
    }
    else if(!strcasecmp(pszMode, "dhcp"))
    {
        nMode = IPV4_ADDR_MODE_STATIC;
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_ipv4_addr_gateway(
                  hPMD,
                  pszIfName,
                  nMode,
                  pszPrefix,
                  pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszMode);
    PMD_SAFE_FREE_MEMORY(pszPrefix);
    PMD_SAFE_FREE_MEMORY(pszGateway);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_static_ipv6_addr(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszPrefix = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "prefix", &pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_static_ipv6_addr(hPMD, pszIfName, pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszPrefix);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_delete_static_ipv6_addr(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszPrefix = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "prefix", &pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_static_ipv6_addr(hPMD, pszIfName, pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszPrefix);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_ipv6_gateway(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszGateway = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv6_gateway(hPMD, pszIfName, &pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("gateway", pszGateway, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszGateway);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_ipv6_gateway(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszGateway = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "gateway", &pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_ipv6_gateway(hPMD, pszIfName, pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszGateway);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_ipv6_addr_mode(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    PKEYVALUE pKeyValues = NULL;
    uint32_t nDhcp = 0;
    uint32_t nAutoConf = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv6_addr_mode(
                  hPMD,
                  pszIfName,
                  &nDhcp,
                  &nAutoConf);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_ipv6_addr_mode(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDhcp = NULL;
    char *pszAutoConf = NULL;
    json_t *pJson = NULL;
    uint32_t nEnableDhcp = 0;
    uint32_t nEnableAutoConf = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "enable_dhcp", &pszDhcp);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "enable_autoconf", &pszAutoConf);
    BAIL_ON_PMD_ERROR(dwError);

    nEnableDhcp = !strcasecmp(pszDhcp, "true") ? 1 : 0;
    nEnableAutoConf = !strcasecmp(pszAutoConf, "true") ? 1 : 0;

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_ipv6_addr_mode(
                  hPMD,
                  pszIfName,
                  nEnableDhcp,
                  nEnableAutoConf);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszDhcp);
    PMD_SAFE_FREE_MEMORY(pszAutoConf);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
get_link_info_json_string(
    NET_LINK_INFO *pLinkInfo,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    size_t i = 0;
    size_t dwCount = 0;
    NET_LINK_INFO *pTemp = NULL;

    if(!pLinkInfo || !ppszJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRoot = json_array();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for (pTemp = pLinkInfo; pTemp; pTemp = pTemp->pNext)
    {
        json_t *pObj = json_object();
        json_object_set_new(pObj, "interface", json_string(pTemp->pszInterfaceName));
        json_object_set_new(pObj, "mac_address", json_string(pTemp->pszMacAddress));
        json_object_set_new(pObj, "mtu", json_integer(pTemp->mtu));
        json_object_set_new(pObj, "mode", json_integer(pTemp->mode));
        json_array_append_new(pRoot, pObj);
    }

    pszJson = json_dumps(pRoot, 0);

    *ppszJson = pszJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppszJson)
    {
        *ppszJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszJson);
    goto cleanup;
}

uint32_t
net_rest_get_link_info(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMode = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    NET_LINK_INFO *pLinkInfo = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_info(hPMD, pszIfName, &pLinkInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_link_info_json_string(pLinkInfo, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    nm_free_link_info(pLinkInfo);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_link_mode(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMode = NULL;
    json_t *pJson = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_mode(hPMD, pszIfName, &linkMode);
    BAIL_ON_PMD_ERROR(dwError);

    if(linkMode == LINK_AUTO)
    {
        pszLinkMode = "auto";
    }
    else if(linkMode == LINK_MANUAL)
    {
        pszLinkMode = "manual";
    }

    dwError = json_string_from_key_value("link_mode", pszLinkMode, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_link_mode(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMode = NULL;
    json_t *pJson = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "link_mode", &pszLinkMode);
    BAIL_ON_PMD_ERROR(dwError);

    if(!strcasecmp(pszLinkMode, "auto"))
    {
        linkMode = LINK_AUTO;
    }
    else if(!strcasecmp(pszLinkMode, "manual"))
    {
        linkMode = LINK_MANUAL;
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_link_mode(hPMD, pszIfName, linkMode);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszLinkMode);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_link_mtu(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMTU = NULL;
    json_t *pJson = NULL;
    uint32_t dwMTU = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_mtu(hPMD, pszIfName, &dwMTU);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszLinkMTU, "%d", dwMTU);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("link_mtu", pszLinkMTU, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszLinkMTU);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_link_mtu(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMTU = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "link_mtu", &pszLinkMTU);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_link_mtu(hPMD, pszIfName, atoi(pszLinkMTU));
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszLinkMTU);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_link_state(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkState = "down";
    json_t *pJson = NULL;
    NET_LINK_STATE linkState;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_link_state(hPMD, pszIfName, &linkState);
    BAIL_ON_PMD_ERROR(dwError);

    if(linkState == LINK_UP)
    {
        pszLinkState = "up";
    }

    dwError = json_string_from_key_value("link_state", pszLinkState, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_link_state(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkState = NULL;
    json_t *pJson = NULL;
    NET_LINK_STATE linkState = LINK_DOWN;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "link_state", &pszLinkState);
    BAIL_ON_PMD_ERROR(dwError);

    if(!strcasecmp(pszLinkState, "up"))
    {
        linkState = LINK_UP;
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_link_state(hPMD, pszIfName, linkState);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszLinkState);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_mac_addr(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_mac_addr(hPMD, pszIfName, &pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("mac_address", pszMacAddr, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszMacAddr);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_mac_addr(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "mac_address", &pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_mac_addr(hPMD, pszIfName, pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszMacAddr);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_version(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = json_string_from_key_value("version", "1.0.4", &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_ntp_servers(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    size_t nCount = 0;
    size_t i = 0;
    char **ppszNtpServers = NULL;
    json_t *pRoot = NULL;
    json_t *pServerArray = NULL;
    char *pszMode = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nCount = 1;
    dwError = PMDAllocateMemory(sizeof(char **) * nCount,
                                (void **)&ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString("ntp.eng.vmware.com", &ppszNtpServers[0]);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    if(!pRoot)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pServerArray = json_array();
    json_object_set_new(pRoot, "servers", pServerArray);
    for(i = 0; i < nCount; ++i)
    {
        json_array_append_new(pServerArray, json_string(ppszNtpServers[i]));
    }

    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    for(i = 0; i < nCount; ++i)
    {
        PMD_SAFE_FREE_MEMORY(ppszNtpServers[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszNtpServers);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_put_ntp_servers(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char **ppszServers = NULL;
    json_t *pJson = NULL;
    int nCount = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_array(pJson,
                                    "servers",
                                    &nCount,
                                    &ppszServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_ntp_servers(hPMD, nCount, ppszServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMDFreeStringArrayWithCount(ppszServers, nCount);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_delete_ntp_servers(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char **ppszServers = NULL;
    json_t *pJson = NULL;
    int nCount = 0;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_array(pJson,
                                    "servers",
                                    &nCount,
                                    &ppszServers);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMDFreeStringArrayWithCount(ppszServers, nCount);
    if(pJson)
    {
        json_decref(pJson);
    }
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_get_hostname(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszHostname = NULL;
    json_t *pJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_hostname(hPMD, &pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("hostname", pszHostname, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszHostname);
    rpc_free_handle(hPMD);
    return dwError;
error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_set_hostname(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszHostname = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "hostname", &pszHostname);
    BAIL_ON_PMD_ERROR(dwError);
 
    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_hostname(hPMD, pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszHostname);
    rpc_free_handle(hPMD);
    return dwError;
error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_waitforlink(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0, dwTimeout = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszTimeout = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "timeout", &pszTimeout);
    if(dwError == ENOENT)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);
    if (pszTimeout)
    {
        if (sscanf(pszTimeout, "%u", &dwTimeout) != 1)
        {
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_wait_for_link_up(hPMD, pszIfName, dwTimeout);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszTimeout);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

uint32_t
net_rest_waitforip(
    void *pInput,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0, dwTimeout = 0, dwAddrTypes = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszTimeout = NULL;
    char *pszAddrTypes = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = NULL;
    PPMDHANDLE hPMD = NULL;
    PREST_FN_ARGS pArgs = (PREST_FN_ARGS)pInput;

    if(!pArgs || IsNullOrEmptyString(pArgs->pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszInputJson = pArgs->pszInputJson;

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "timeout", &pszTimeout);
    if(dwError == ENOENT)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);
    if (pszTimeout)
    {
        if (sscanf(pszTimeout, "%u", &dwTimeout) != 1)
        {
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = json_get_string_value(pJson, "addrtype", &pszAddrTypes);
    BAIL_ON_PMD_ERROR(dwError);

    if (strstr(pszAddrTypes, "ipv4"))
    {
        dwAddrTypes |= NET_ADDR_IPV4;
    }
    if (strstr(pszAddrTypes, "ipv6"))
    {
        dwAddrTypes |= NET_ADDR_IPV6;
    }

    dwError = net_open_privsep_rest(pArgs->pAuthArgs->pRestAuth, &hPMD);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_wait_for_ip(
                  hPMD,
                  pszIfName,
                  dwTimeout,
                  dwAddrTypes);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszTimeout);
    PMD_SAFE_FREE_MEMORY(pszAddrTypes);
    rpc_free_handle(hPMD);
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}
