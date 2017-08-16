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

REST_MODULE _net_rest_module[] =
{
    {
        "/v1/net/dns/domains",
        {net_rest_get_dns_domains, net_rest_put_dns_domains, NULL, NULL}
    },
    {
        "/v1/net/dns/servers",
        {net_rest_get_dns_servers, net_rest_put_dns_servers, NULL, NULL}
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
        "/v1/net/firewall/rule",
        {
            net_rest_get_firewall_rule,
            net_rest_put_firewall_rule,
            NULL,
            net_rest_delete_firewall_rule
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

uint32_t
net_rest_put_dns_servers(
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_dns_servers(pszIfName,
                                 mode,
                                 (size_t)nCount,
                                 (const char **)ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pRoot = json_object();
    pszOutputJson = json_dumps(pRoot, 0);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    PMD_SAFE_FREE_MEMORY(pszMode);
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
    void *pInputJson,
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

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_dns_servers(pszIfName,
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
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_dns_domains(pszIfName, &nCount, &ppszDnsDomains);
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
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_array(pJson,
                                        "domains",
                                        (int *)&nCount,
                                        &ppszDnsDomains);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_set_dns_domains(pszIfName,
                                 nCount,
                                 (const char**)ppszDnsDomains);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDuid= NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_get_duid(pszIfName, &pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("duid", pszDuid, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszDuid);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszDuid= NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_duid(pszIfName, pszDuid);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszIaid= NULL;
    json_t *pJson = NULL;
    uint32_t nIaid = 0;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_iaid(pszIfName, &nIaid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszIaid, "%d", nIaid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("iaid", pszIaid, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIaid);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszIaid= NULL;
    json_t *pJson = NULL;
    int nIaid = 0;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_iaid(pszIfName, nIaid);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszIfName);
    PMD_SAFE_FREE_MEMORY(pszIaid);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_ifdown(pszIfName);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_ifup(pszIfName);
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
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_get_ip_addr(pszIfName, nAddrTypes, &dwCount, &ppIpAddr);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    PNET_IP_ROUTE *ppIpRoutes = NULL;
    size_t dwCount = 0;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!IsNullOrEmptyString(pszInputJson))
    {
        dwError = get_json_object_from_string(pszInputJson, &pJson);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = json_get_string_value(pJson, "interface", &pszIfName);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_static_ip_routes(pszIfName, &dwCount, &ppIpRoutes);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_route_array_json_string(dwCount, ppIpRoutes, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
    PMD_SAFE_FREE_MEMORY(pszIfName);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    NET_IP_ROUTE stIpRoute = {0};
    size_t dwCount = 0;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_add_static_ip_route(&stIpRoute);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
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
net_rest_delete_static_ip_route(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    NET_IP_ROUTE stIpRoute = {0};
    size_t dwCount = 0;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_delete_static_ip_route(&stIpRoute);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
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
net_rest_get_ipv4_gateway(
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_ipv4_addr_gateway(pszIfName,
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
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_ipv4_addr_gateway(pszIfName,
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszPrefix = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "prefix", &pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_add_static_ipv6_addr(pszIfName, pszPrefix);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszPrefix = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "prefix", &pszPrefix);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_delete_static_ipv6_addr(pszIfName, pszPrefix);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszGateway = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_ipv6_gateway(pszIfName, &pszGateway);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszGateway = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "gateway", &pszGateway);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_ipv6_gateway(pszIfName, pszGateway);
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
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_ipv6_addr_mode(pszIfName, &nDhcp, &nAutoConf);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
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
    void *pInputJson,
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
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_ipv6_addr_mode(pszIfName, nEnableDhcp, nEnableAutoConf);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;
    NET_LINK_INFO *pLinkInfo = NULL;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_link_info(pszIfName, &pLinkInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_link_info_json_string(pLinkInfo, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    nm_free_link_info(pLinkInfo);
    if(pJson)
    {
        json_decref(pJson);
    }
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMode = NULL;
    json_t *pJson = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_link_mode(pszIfName, &linkMode);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMode = NULL;
    json_t *pJson = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_link_mode(pszIfName, linkMode);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMTU = NULL;
    json_t *pJson = NULL;
    uint32_t dwMTU = 0;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_link_mtu(pszIfName, &dwMTU);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkMTU = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "link_mtu", &pszLinkMTU);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_link_mtu(pszIfName, atoi(pszLinkMTU));
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkState = "down";
    json_t *pJson = NULL;
    NET_LINK_STATE linkState;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_link_state(pszIfName, &linkState);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszLinkState = NULL;
    json_t *pJson = NULL;
    NET_LINK_STATE linkState = LINK_DOWN;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_set_link_state(pszIfName, linkState);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_get_link_mac_addr(pszIfName, &pszMacAddr);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszMacAddr = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "interface", &pszIfName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "mac_address", &pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_link_mac_addr(pszIfName, pszMacAddr);
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
    void *pInputJson,
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char **ppszServers = NULL;
    json_t *pJson = NULL;
    int nCount = 0;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char **ppszServers = NULL;
    json_t *pJson = NULL;
    int nCount = 0;
    const char *pszInputJson = pInputJson;

    if(IsNullOrEmptyString(pszInputJson) || !ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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
get_firewall_rules_json_string(
    size_t dwCount,
    NET_FW_RULE **ppFwRules,
    char **ppszJson
    )
{
    uint32_t dwError = 0;
    char *pszJson = NULL;
    json_t *pRoot = NULL;
    size_t i = 0;

    if(dwCount == 0 || !ppFwRules || !ppszJson)
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
        PNET_FW_RULE pFwRule = ppFwRules[i];
        json_array_append_new(pRoot, json_string(pFwRule->pszRawFwRule));
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
net_rest_get_firewall_rule(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    PNET_FW_RULE *ppFwRules = NULL;
    size_t dwCount = 0;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_firewall_rules(&dwCount, &ppFwRules);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_firewall_rules_json_string(dwCount, ppFwRules, &pszOutputJson);
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
net_rest_put_firewall_rule(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszFwRule = NULL;
    json_t *pJson = NULL;
    NET_FW_RULE netFwRule = {0};
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson || IsNullOrEmptyString(pszInputJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "rule", &pszFwRule);
    BAIL_ON_PMD_ERROR(dwError);

    netFwRule.ipVersion = IPV4;
    netFwRule.type = FW_RAW;
    netFwRule.pszRawFwRule = pszFwRule;

    dwError = nm_add_firewall_rule(&netFwRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
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
net_rest_delete_firewall_rule(
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszFwRule = NULL;
    json_t *pJson = NULL;
    NET_FW_RULE netFwRule = {0};
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson || IsNullOrEmptyString(pszInputJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "rule", &pszFwRule);
    BAIL_ON_PMD_ERROR(dwError);

    netFwRule.ipVersion = IPV4;
    netFwRule.type = FW_RAW;
    netFwRule.pszRawFwRule = pszFwRule;

    dwError = nm_delete_firewall_rule(&netFwRule);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_make_result_success(&pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    if(pJson)
    {
        json_decref(pJson);
    }
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszHostname = NULL;
    json_t *pJson = NULL;

    if(!ppOutputJson)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = nm_get_hostname(&pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_string_from_key_value("hostname", pszHostname, &pszOutputJson);
    BAIL_ON_PMD_ERROR(dwError);

    *ppOutputJson = pszOutputJson;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszHostname);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0;
    char *pszOutputJson = NULL;
    char *pszHostname = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson || IsNullOrEmptyString(pszInputJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_json_object_from_string(pszInputJson, &pJson);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_string_value(pJson, "hostname", &pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = nm_set_hostname(pszHostname);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0, dwTimeout = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszTimeout = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson || IsNullOrEmptyString(pszInputJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_wait_for_link_up(pszIfName, dwTimeout);
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
    void *pInputJson,
    void **ppOutputJson
    )
{
    uint32_t dwError = 0, dwTimeout = 0, dwAddrTypes = 0;
    char *pszOutputJson = NULL;
    char *pszIfName = NULL;
    char *pszTimeout = NULL;
    char *pszAddrTypes = NULL;
    json_t *pJson = NULL;
    const char *pszInputJson = pInputJson;

    if(!ppOutputJson || IsNullOrEmptyString(pszInputJson))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

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

    dwError = nm_wait_for_ip(pszIfName, dwTimeout, dwAddrTypes);
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
    return dwError;

error:
    if(ppOutputJson)
    {
        *ppOutputJson = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszOutputJson);
    goto cleanup;
}

