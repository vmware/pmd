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

uint32_t
netmgr_print_error(
    PPMDHANDLE hPMD,
    uint32_t dwErrorCode
    );

static const char *
link_state_to_string(
    NET_LINK_STATE state
)
{
    switch (state)
    {
        case RPC_LINK_DOWN:
            return "down";
        case RPC_LINK_UP:
            return "up";
        default:
            return "unknown";
    }
}

static const char *
link_mode_to_string(
    NET_RPC_LINK_MODE mode
)
{
    switch (mode)
    {
        case RPC_LINK_AUTO:
            return "auto";
        case RPC_LINK_MANUAL:
            return "manual";
        default:
            return "unknown";
    }
}

const char *
ip_addr_type_to_string(
    NET_ADDR_TYPE addrType
)
{
    switch (addrType)
    {
        case STATIC_IPV4:
            return "IPv4 static";
        case STATIC_IPV6:
            return "IPv6 static";
        case DHCP_IPV4:
            return "IPv4 dhcp";
        case DHCP_IPV6:
            return "IPv6 dhcp";
        case AUTO_IPV6:
            return "IPv6 autoconf";
        case LINK_LOCAL_IPV6:
            return "IPv6 link-local";
        default:
            break;
    }
    return "Unknown addrtype";
}

static uint32_t
cmd_link_info(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, mtu = 0;
    char *pszIfname = NULL, *pszLinkMode = NULL, *pszLinkState = NULL;
    char *pszMacAddr = NULL, *pszMtu = NULL, *pszEnd = NULL;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    NET_LINK_INFO *pLinkInfo = NULL, *cur = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    switch (pCmd->op)
    {
        case OP_SET:
            dwError = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgrcli_find_cmdopt(pCmd, "macaddr", &pszMacAddr);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            if (pszMacAddr != NULL)
            {
                dwError = netmgr_client_set_mac_addr(hPMD,
                                                     pszIfname,
                                                     pszMacAddr);
                BAIL_ON_CLI_ERROR(dwError);
            }

            dwError = netmgrcli_find_cmdopt(pCmd, "mode", &pszLinkMode);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            if (pszLinkMode != NULL)
            {
                if (!strcmp(pszLinkMode, "manual"))
                {
                    linkMode = LINK_MANUAL;
                }
                else if (!strcmp(pszLinkMode, "auto"))
                {
                    linkMode = LINK_AUTO;
                }
                dwError = netmgr_client_set_link_mode(hPMD,
                                                      pszIfname,
                                                      linkMode);
                BAIL_ON_CLI_ERROR(dwError);
            }

            dwError = netmgrcli_find_cmdopt(pCmd, "mtu", &pszMtu);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            if (pszMtu != NULL)
            {
                mtu = (uint32_t)strtoul(pszMtu, &pszEnd, 10);
                dwError = netmgr_client_set_link_mtu(hPMD, pszIfname, mtu);
                BAIL_ON_CLI_ERROR(dwError);
            }

            dwError = netmgrcli_find_cmdopt(pCmd, "state", &pszLinkState);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            if (pszLinkState != NULL)
            {
                if (!strcmp(pszLinkState, "up"))
                {
                    dwError = netmgr_client_ifup(hPMD, pszIfname);
                }
                else if (!strcmp(pszLinkState, "down"))
                {
                    dwError = netmgr_client_ifdown(hPMD, pszIfname);
                }
                BAIL_ON_CLI_ERROR(dwError);
            }
            break;

        case OP_GET:
            dwError = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgr_client_get_link_info(hPMD,
                                                  pszIfname,
                                                  &pLinkInfo);
            BAIL_ON_CLI_ERROR(dwError);

            fprintf(stdout, "%-10s\t%-17s\t%-10s\t%-10s\t%-10s\n", "Name",
                    "MacAddress", "Mode", "MTU", "State");
            for (cur =  pLinkInfo; cur; cur = cur->pNext)
            {
                fprintf(stdout, "%-10s\t", cur->pszInterfaceName);
                fprintf(stdout, "%-17s\t", cur->pszMacAddress);
                fprintf(stdout, "%-10s\t", link_mode_to_string(cur->mode));
                fprintf(stdout, "%-10u\t", cur->mtu);
                fprintf(stdout, "%-25s\n", link_state_to_string(cur->state));
            }
            break;

        default:
            dwError =  EINVAL;
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    for (cur = pLinkInfo; cur; cur = pLinkInfo)
    {
        pLinkInfo = cur->pNext;
        free(cur->pszMacAddress);
        free(cur->pszInterfaceName);
        free(cur);
    }
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_ip4_address(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0;
    NET_IPV4_ADDR_MODE ip4Mode;
    char *pszIfName = NULL, *pszMode = NULL;
    char *pszIpAddr = NULL, *pszGateway = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfName);

    if (pCmd->op == OP_SET)
    {
        dwError = netmgrcli_find_cmdopt(pCmd, "mode", &pszMode);
        BAIL_ON_CLI_ERROR(dwError);

        if (!strcmp(pszMode, "dhcp"))
        {
            ip4Mode = IPV4_ADDR_MODE_DHCP;
        }
        else if (!strcmp(pszMode, "static"))
        {
            ip4Mode = IPV4_ADDR_MODE_STATIC;
        }
        else if (!strcmp(pszMode, "none"))
        {
            ip4Mode = IPV4_ADDR_MODE_NONE;
        }
        else
        {
            dwError = EINVAL;
            BAIL_ON_CLI_ERROR(dwError);
        }

        netmgrcli_find_cmdopt(pCmd, "address", &pszIpAddr);

        netmgrcli_find_cmdopt(pCmd, "gateway", &pszGateway);

        dwError = netmgr_client_set_ipv4_addr_gateway(hPMD,
                                                      pszIfName,
                                                      ip4Mode,
                                                      pszIpAddr,
                                                      pszGateway);
        pszIpAddr = NULL;
        pszGateway = NULL;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_GET)
    {
        dwError = netmgr_client_get_ipv4_addr_gateway(hPMD,
                                                      pszIfName,
                                                      &ip4Mode,
                                                      &pszIpAddr,
                                                      &pszGateway);
        BAIL_ON_CLI_ERROR(dwError);

        if (ip4Mode == IPV4_ADDR_MODE_NONE)
        {
            fprintf(stdout, "IPv4 Address Mode: none\n");
        }
        else if (ip4Mode == IPV4_ADDR_MODE_DHCP)
        {
            fprintf(stdout, "IPv4 Address Mode: dhcp\n");
        }
        else
        {
            fprintf(stdout, "IPv4 Address Mode: static\n");
        }
        if (pszIpAddr != NULL)
        {
            fprintf(stdout, "IPv4 Address=%s\n", pszIpAddr);
        }
        if (pszGateway != NULL)
        {
            fprintf(stdout, "IPv4 Gateway=%s\n", pszGateway);
        }
    }

cleanup:
    /* Free allocated memory */
    PMD_CLI_SAFE_FREE_MEMORY(pszIpAddr);
    PMD_CLI_SAFE_FREE_MEMORY(pszGateway);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_ip6_address(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, dhcp = 0, autoconf = 0;
    char *pszIfName = NULL, *pszDhcp = NULL, *pszAutoconf = NULL;
    char *a1, *a2, *pszIpAddrList = NULL, *pszGateway = NULL;
    NET_IP_ADDR **ppIpAddrList = NULL;
    size_t i, count = 0;
    CMD_OP addrOp = OP_MAX;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfName);

    switch (pCmd->op)
    {
        case OP_ADD:
        case OP_DEL:
            dwError = netmgrcli_find_cmdopt(pCmd, "addrlist", &pszIpAddrList);
            if (dwError != ENOENT)
            {
                BAIL_ON_CLI_ERROR(dwError);
            }
            if (pszIpAddrList != NULL)
            {
                a2 = pszIpAddrList;
                do {
                    a1 = strsep(&a2, ",");
                    if (strlen(a1) == 0)
                    {
                        continue;
                    }
                    if (pCmd->op == OP_ADD)
                    {
                        dwError = netmgr_client_add_static_ipv6_addr(
                                                hPMD,
                                                pszIfName,
                                                a1);
                    }
                    else
                    {
                        dwError = netmgr_client_delete_static_ipv6_addr(
                                                hPMD,
                                                pszIfName,
                                                a1);
                    }
                    BAIL_ON_CLI_ERROR(dwError);
                } while (a2 != NULL);
            }

            dwError = netmgrcli_find_cmdopt(pCmd, "gateway", &pszGateway);
            if (dwError != ENOENT)
            {
                BAIL_ON_CLI_ERROR(dwError);
            }

            if (pszGateway)
            {
                if (pCmd->op == OP_ADD)
                {
                    dwError = netmgr_client_set_ipv6_gateway(hPMD,
                                                             pszIfName,
                                                             pszGateway);
                }
                else
                {
                    dwError = netmgr_client_set_ipv6_gateway(hPMD,
                                                             pszIfName,
                                                             NULL);
                }
                BAIL_ON_CLI_ERROR(dwError);
            }
            /* fall through */

        case OP_SET:
            dwError = netmgrcli_find_cmdopt(pCmd, "dhcp", &pszDhcp);
            if (dwError != ENOENT)
            {
                BAIL_ON_CLI_ERROR(dwError);
            }
            dwError = netmgrcli_find_cmdopt(pCmd, "autoconf", &pszAutoconf);
            if (dwError != ENOENT)
            {
                BAIL_ON_CLI_ERROR(dwError);
            }

            if (pszDhcp != NULL)
            {
                if (!strcmp(pszDhcp, "1"))
                {
                    dhcp = 1;
                }
            }
            if (pszAutoconf != NULL)
            {
                if (!strcmp(pszAutoconf, "1"))
                {
                    autoconf = 1;
                }
            }

            dwError = netmgr_client_set_ipv6_addr_mode(hPMD,
                                                       pszIfName,
                                                       dhcp,
                                                       autoconf);
            BAIL_ON_CLI_ERROR(dwError);
            break;

        case OP_GET:
            dwError = netmgr_client_get_ipv6_addr_mode(hPMD,
                                                       pszIfName,
                                                       &dhcp,
                                                       &autoconf);
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgr_client_get_ip_addr(
                                    hPMD,
                                    pszIfName,
                                    STATIC_IPV6 | AUTO_IPV6 | DHCP_IPV6,
                                    &count,
                                    &ppIpAddrList);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgr_client_get_ipv6_gateway(hPMD,
                                                     pszIfName,
                                                     &pszGateway);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }

            if (dhcp)
            {
                fprintf(stdout, "DHCP IPv6 enabled\n");
            }
            if (autoconf)
            {
                fprintf(stdout, "Autoconf IPv6 enabled\n");
            }
            for (i = 0; i < count; i++)
            {
                fprintf(stdout, "%s Address=%s\n",
                        ip_addr_type_to_string(ppIpAddrList[i]->type),
                        ppIpAddrList[i]->pszIPAddrPrefix);
            }
            if (pszGateway)
            {
                fprintf(stdout, "IPv6 Gateway=%s", pszGateway);
            }
            fprintf(stdout, "\n");
            break;

        default:
            dwError = EINVAL;
    }

cleanup:
    /* Free allocated memory */
    for (i = 0; i < count; i++)
    {
        PMD_CLI_SAFE_FREE_MEMORY(ppIpAddrList[i]->pszInterfaceName);
        PMD_CLI_SAFE_FREE_MEMORY(ppIpAddrList[i]->pszIPAddrPrefix);
        PMD_CLI_SAFE_FREE_MEMORY(ppIpAddrList[i]);
    }
    PMD_CLI_SAFE_FREE_MEMORY(ppIpAddrList);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_ip_route(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0;
    size_t i, dwCount = 0;
    char *pszMetric = NULL, *pszScope = NULL;
    NET_IP_ROUTE ipRoute = {0}, **ppRoutesList = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    netmgrcli_find_cmdopt(pCmd, "interface", &ipRoute.pszInterfaceName);

    switch (pCmd->op)
    {
        case OP_ADD:
            netmgrcli_find_cmdopt(pCmd, "gateway", &ipRoute.pszGateway);

            dwError = netmgrcli_find_cmdopt(pCmd, "metric", &pszMetric);
            if (dwError == ENOENT)
            {
                dwError = 0;
                ipRoute.metric = 1024;
            }
            else
            {
                sscanf(pszMetric, "%u", &ipRoute.metric);
            }
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgrcli_find_cmdopt(pCmd, "scope", &pszScope);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            /* fall through */

        case OP_DEL:
            netmgrcli_find_cmdopt(pCmd, "destination", &ipRoute.pszDestNetwork);

            if (pCmd->op == OP_ADD)
            {
                dwError = netmgr_client_add_static_ip_route(hPMD, &ipRoute);
            }
            else
            {
                dwError = netmgr_client_delete_static_ip_route(hPMD, &ipRoute);
            }
            BAIL_ON_CLI_ERROR(dwError);
            break;

        case OP_GET:
            dwError = netmgr_client_get_static_ip_routes(
                                        hPMD,
                                        ipRoute.pszInterfaceName,
                                        &dwCount,
                                        &ppRoutesList);
            BAIL_ON_CLI_ERROR(dwError);

            fprintf(stdout, "Static IP Routes:\n");
            for (i = 0; i < dwCount; i++)
            {
                fprintf(stdout, "Route #%zu\n", i+1);
                fprintf(stdout, "  Dest=%s\n", ppRoutesList[i]->pszDestNetwork);
                fprintf(stdout, "  Gateway=%s\n", ppRoutesList[i]->pszGateway);
                fprintf(stdout, "  Scope=%u\n", ppRoutesList[i]->scope);
                fprintf(stdout, "  Metric=%u\n", ppRoutesList[i]->metric);
            }
            fprintf(stdout, "\n");
            break;

        default:
            dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    for (i = 0; i < dwCount; i++)
    {
        PMD_SAFE_FREE_MEMORY(ppRoutesList[i]->pszInterfaceName);
        PMD_SAFE_FREE_MEMORY(ppRoutesList[i]->pszDestNetwork);
        PMD_SAFE_FREE_MEMORY(ppRoutesList[i]->pszSourceNetwork);
        PMD_SAFE_FREE_MEMORY(ppRoutesList[i]->pszGateway);
        PMD_SAFE_FREE_MEMORY(ppRoutesList[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppRoutesList);
    return dwError;

error:
    goto cleanup;
}

static unsigned32
netmgr_parse_comma_sep_tokens(
    char *pszCommaSepTokens,
    uint32_t *add_servers,
    size_t *dwCount,
    char ***ppszCommaSepTokenList
)
{
    uint32_t i = 0, add_flag = 0, count = 0, dwError = 0;
    char *pszTokens = NULL, *s1, *s2, **ppszTokensList = NULL;

    if (!dwCount || !ppszCommaSepTokenList || !add_servers)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszCommaSepTokens, &pszTokens);
    BAIL_ON_PMD_ERROR(dwError);
    if (strlen(pszTokens) > 0)
    {
        s2 = pszTokens;
        do {
            s1 = strsep(&s2, ",");
            if (strlen(s1) > 0)
            {
                count++;
            }
        } while (s2 != NULL);
    }
    if (count == 0)
    {
        goto done;
    }
    dwError = PMDAllocateMemory((count * sizeof(char *)),
                                (void **)&ppszTokensList);
    BAIL_ON_PMD_ERROR(dwError);
    strcpy(pszTokens, pszCommaSepTokens);
    s2 = pszTokens;
    do {
        s1 = strsep(&s2, ",");
        if (strlen(s1) > 0)
        {
            if ((i == 0) && !strcmp(s1,"+"))
            {
                add_flag = 1;
                count -= 1;
                continue;
            }
            dwError = PMDAllocateString(s1, &(ppszTokensList[i++]));
            BAIL_ON_PMD_ERROR(dwError);
        }
    } while (s2 != NULL);

done:
    *add_servers = add_flag;
    *dwCount = count;
    *ppszCommaSepTokenList = ppszTokensList;

cleanup:
    PMD_SAFE_FREE_MEMORY(pszTokens);
    return dwError;

error:
    if (add_servers)
    {
        *add_servers = 0;
    }
    if (dwCount)
    {
        *dwCount = 0;
    }
    if (ppszCommaSepTokenList)
    {
        *ppszCommaSepTokenList = NULL;
    }
    for (i = 0; i < count; i++)
    {
        PMD_SAFE_FREE_MEMORY(ppszTokensList[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszTokensList);
    goto cleanup;
}

static uint32_t
cmd_dns_servers(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, add = 0;
    size_t dwCount = 0, i = 0;
    NET_DNS_MODE dnsMode = DNS_MODE_INVALID;
    char *pszIfname = NULL, *pszMode = NULL;
    char *pszDnsServers = NULL, *pszNoRestart = NULL;
    char *s1, *s2, *pszServers = NULL, **ppszDnsServersList = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    switch (pCmd->op)
    {
        case OP_SET:
            dwError = netmgrcli_find_cmdopt(pCmd, "mode", &pszMode);
            BAIL_ON_CLI_ERROR(dwError);
            if (!strcmp(pszMode, "dhcp"))
            {
                dnsMode = DHCP_DNS;
            }
            else if (!strcmp(pszMode, "static"))
            {
                dnsMode = STATIC_DNS;
            }
            /* fall through */
        case OP_ADD:
        case OP_DEL:
            dwError = netmgrcli_find_cmdopt(pCmd, "servers", &pszDnsServers);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);

            if (pszDnsServers != NULL)
            {
                dwError = PMDAllocateString(pszDnsServers, &pszServers);
                BAIL_ON_CLI_ERROR(dwError);
                if (strlen(pszServers) > 0)
                {
                    s2 = pszServers;
                    do {
                        s1 = strsep(&s2, ",");
                        if (strlen(s1) > 0)
                        {
                            dwCount++;
                        }
                    } while (s2 != NULL);
                }
            }
            if (!dwCount && (pCmd->op != OP_SET))
            {
                dwError = EDOM;
                BAIL_ON_CLI_ERROR(dwError);
            }
            if (dwCount > 0)
            {
                dwError = PMDAllocateMemory(
                              (dwCount * sizeof(char*)),
                              (void **)&ppszDnsServersList);
                BAIL_ON_CLI_ERROR(dwError);
                strcpy(pszServers, pszDnsServers);
                s2 = pszServers;
                do {
                    s1 = strsep(&s2, ",");
                    if (strlen(s1) > 0)
                    {
                        dwError = PMDAllocateString(
                                      s1,
                                      &(ppszDnsServersList[i++]));
                        BAIL_ON_CLI_ERROR(dwError);
                    }
                } while (s2 != NULL);
            }
            dwError = netmgrcli_find_cmdopt(pCmd, "norestart", &pszNoRestart);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            if ((pszNoRestart != NULL) && !strcmp(pszNoRestart, "true"))
            {
                //TODO: Handle norestart
            }
            if (pCmd->op == OP_SET)
            {
                dwError = netmgr_client_set_dns_servers(
                              hPMD,
                              pszIfname,
                              dnsMode,
                              dwCount,
                              ppszDnsServersList);
            }
            else if (pCmd->op == OP_ADD)
            {
                dwError = netmgr_client_add_dns_server(
                              hPMD,
                              pszIfname,
                              ppszDnsServersList[0]);
            }
            else if (pCmd->op == OP_DEL)
            {
                dwError = netmgr_client_delete_dns_server(
                              hPMD,
                              pszIfname,
                              ppszDnsServersList[0]);
            }
            break;

        case OP_GET:
            dwError = netmgr_client_get_dns_servers(
                          hPMD,
                          pszIfname,
                          &dnsMode,
                          &dwCount,
                          &ppszDnsServersList);
            BAIL_ON_CLI_ERROR(dwError);

            if (dnsMode == STATIC_DNS)
            {
                fprintf(stdout, "DNSMode=static\n");
            }
            else
            {
                fprintf(stdout, "DNSMode=dhcp\n");
            }

            fprintf(stdout, "DNSServers=");
            for (i = 0; i < dwCount; i++)
            {
                fprintf(stdout, "%s ", ppszDnsServersList[i]);
            }
            fprintf(stdout, "\n");
            break;

        default:
            dwError = EINVAL;
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    /* Free allocated memory */
    for (i = 0; i < dwCount; i++)
    {
        PMD_SAFE_FREE_MEMORY(ppszDnsServersList[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszDnsServersList);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_dns_domains(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, add = 0;
    size_t dwCount = 0, i = 0;
    char *pszDnsDomains = NULL, **ppszDnsDomains = NULL;
    char *pszDomains = NULL, *pszIfname = NULL, *pszNoRestart = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);

    switch (pCmd->op)
    {
        case OP_SET:
        case OP_ADD:
        case OP_DEL:
            dwError = netmgrcli_find_cmdopt(pCmd, "domains", &pszDnsDomains);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgr_parse_comma_sep_tokens(
                          pszDnsDomains,
                          &add,
                          &dwCount,
                          &ppszDnsDomains);
            BAIL_ON_PMD_ERROR(dwError);

            if (!dwCount && (pCmd->op != OP_SET))
            {
                dwError = EDOM;
                BAIL_ON_CLI_ERROR(dwError);
            }
            dwError = netmgrcli_find_cmdopt(pCmd, "norestart", &pszNoRestart);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);
            if ((pszNoRestart != NULL) && !strcmp(pszNoRestart, "true"))
            {
                //TODO: Handle
            }
            if (pCmd->op == OP_SET)
            {
                dwError = netmgr_client_set_dns_domains(
                              hPMD,
                              pszIfname,
                              dwCount,
                              ppszDnsDomains);
            }
            else if (pCmd->op == OP_ADD)
            {
                dwError = netmgr_client_add_dns_domain(
                              hPMD,
                              pszIfname,
                              ppszDnsDomains[0]);
            }
            else if (pCmd->op == OP_DEL)
            {
                dwError = netmgr_client_delete_dns_domain(
                              hPMD,
                              pszIfname,
                              ppszDnsDomains[0]);
                BAIL_ON_CLI_ERROR(dwError);
            }
            BAIL_ON_CLI_ERROR(dwError);
            break;

        case OP_GET:
            dwError = netmgr_client_get_dns_domains(
                          hPMD,
                          pszIfname,
                          &dwCount,
                          &ppszDnsDomains);
            BAIL_ON_CLI_ERROR(dwError);

            fprintf(stdout, "Domains=");
            for (i = 0; i < dwCount; i++)
            {
                fprintf(stdout, "%s ", ppszDnsDomains[i]);
            }
            fprintf(stdout, "\n");
            break;

        default:
            dwError = EINVAL;
    }
cleanup:
    /* Free allocated memory */
    for (i = 0; i < dwCount; i++)
    {
        PMD_SAFE_FREE_MEMORY(ppszDnsDomains[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszDnsDomains);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_if_iaid(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, dwIaid;
    char *pszIaid = NULL, *pszIfname = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
    BAIL_ON_CLI_ERROR(dwError);

    if (pCmd->op == OP_SET)
    {
        dwError = netmgrcli_find_cmdopt(pCmd, "iaid", &pszIaid);
        BAIL_ON_CLI_ERROR(dwError);

        dwError = netmgr_client_set_iaid(hPMD, pszIfname, atoi(pszIaid));
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_GET)
    {
        dwError = netmgr_client_get_iaid(hPMD, pszIfname, &dwIaid);
        BAIL_ON_CLI_ERROR(dwError);
        fprintf(stdout, "IAID=%u\n", dwIaid);
    }

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_dhcp_duid(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0;
    char *pszDuid = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_SET)
    {
        dwError = netmgrcli_find_cmdopt(pCmd, "duid", &pszDuid);
        BAIL_ON_CLI_ERROR(dwError);

        dwError = netmgr_client_set_duid(hPMD, NULL, pszDuid);
        pszDuid = NULL;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_GET)
    {
        dwError = netmgr_client_get_duid(hPMD, NULL, &pszDuid);
        BAIL_ON_CLI_ERROR(dwError);
        fprintf(stdout, "DUID=%s\n", pszDuid);
    }

cleanup:
    /* Free allocated memory */
    PMD_CLI_SAFE_FREE_MEMORY(pszDuid);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_ntp_servers(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd
    )
{
    uint32_t dwError = 0;
    char **ppszServers = NULL;
    size_t nServers = 0;
    uint32_t dummy = 0;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_SET || pCmd->op == OP_ADD || pCmd->op == OP_DEL)
    {
        char *pszServersCmdLine = NULL;
        dwError = netmgrcli_find_cmdopt(pCmd, "servers", &pszServersCmdLine);
        BAIL_ON_CLI_ERROR(dwError);

        dwError = netmgr_parse_comma_sep_tokens(
                      pszServersCmdLine,
                      &dummy,
                      &nServers,
                      &ppszServers);
        BAIL_ON_PMD_ERROR(dwError);

        switch(pCmd->op)
        {
            case OP_SET:
                dwError = netmgr_client_set_ntp_servers(
                              hPMD,
                              nServers,
                              ppszServers);
                BAIL_ON_CLI_ERROR(dwError);
                break;
            case OP_ADD:
                dwError = netmgr_client_add_ntp_servers(
                              hPMD,
                              nServers,
                              (const char **)ppszServers);
                BAIL_ON_CLI_ERROR(dwError);
                break;
            case OP_DEL:
                dwError = netmgr_client_delete_ntp_servers(
                              hPMD,
                              nServers,
                              (const char **)ppszServers);
                BAIL_ON_CLI_ERROR(dwError);
                break;
            default:
                break;
        }
    }
    else if (pCmd->op == OP_GET)
    {
        int i = 0;
        dwError = netmgr_client_get_ntp_servers(hPMD, &nServers, &ppszServers);
        BAIL_ON_CLI_ERROR(dwError);
        for(i = 0; i < nServers; ++i)
        {
            fprintf(stdout,
                    "%s%s",
                    ppszServers[i],
                    (i+1) < nServers ? "," : "");
        }
        fprintf(stdout, "\n");
    }

cleanup:
    /* Free allocated memory */
    PMDFreeStringArrayWithCount(ppszServers, nServers);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_hostname(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0;
    char *pszHostname = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_SET)
    {
        dwError = netmgrcli_find_cmdopt(pCmd, "hostname", &pszHostname);
        BAIL_ON_CLI_ERROR(dwError);

        dwError = netmgr_client_set_hostname(hPMD, pszHostname);
        pszHostname = NULL;
        BAIL_ON_CLI_ERROR(dwError);
    }

    if (pCmd->op == OP_GET)
    {
        dwError = netmgr_client_get_hostname(hPMD, &pszHostname);
        BAIL_ON_CLI_ERROR(dwError);
        fprintf(stdout, "Hostname: %s\n", pszHostname);
    }

cleanup:
    /* Free allocated memory */
    PMD_CLI_SAFE_FREE_MEMORY(pszHostname);
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_wait_for_link(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0;
    long int ltimeout = 0;
    char *pszIfname = NULL, *pszTimeOut = NULL, *pszEnd = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = netmgrcli_find_cmdopt(pCmd, "timeout", &pszTimeOut);
    BAIL_ON_CLI_ERROR(dwError);

    if ((ltimeout = strtol(pszTimeOut, &pszEnd, 10)) < 0)
    {
        dwError= ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = netmgr_client_wait_for_link_up(hPMD,
                                             pszIfname,
                                             (uint32_t)ltimeout);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

typedef struct _NM_CLI_ADDR_STR_TYPE
{
    char *pszIpAddrType;
    NET_ADDR_TYPE ipAddrType;
} NM_CLI_ADDR_STR_TYPE, *PNM_CLI_ADDR_STR_TYPE;

NM_CLI_ADDR_STR_TYPE addrStrToTypeMap[] =
{
    { "ipv4",               NET_ADDR_IPV4       },
    { "ipv6",               NET_ADDR_IPV6       },
    { "static_ipv4",        STATIC_IPV4         },
    { "static_ipv6",        STATIC_IPV6         },
    { "dhcp_ipv4",          DHCP_IPV4           },
    { "dhcp_ipv6",          DHCP_IPV6           },
    { "auto_ipv6",          AUTO_IPV6           },
    { "link_local_ipv6",    LINK_LOCAL_IPV6     },
};

static uint32_t
get_ip_addrtype(
    const char *pszAddrType,
    NET_ADDR_TYPE *pIpAddrType)
{
    uint32_t dwError = 0;
    NET_ADDR_TYPE addrType = 0;
    size_t i = 0, addrTypeCount = 0;

    if (IsNullOrEmptyString(pszAddrType) || !pIpAddrType)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    addrTypeCount = sizeof(addrStrToTypeMap)/sizeof(NM_CLI_ADDR_STR_TYPE);
    for (i = 0; i < addrTypeCount; i++)
    {
        if (!strcmp(pszAddrType, addrStrToTypeMap[i].pszIpAddrType))
        {
            addrType = addrStrToTypeMap[i].ipAddrType;
            break;
        }
    }

    if (!addrType)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pIpAddrType = addrType;

cleanup:
    return dwError;

error:
    if (pIpAddrType)
    {
        *pIpAddrType = 0;
    }
    goto cleanup;
}

static uint32_t
cmd_wait_for_ip(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, dummy = 0;
    long int ltimeout = 0;
    char *pszIfname = NULL, *pszTimeOut = NULL, *pszEnd = NULL;
    char *pszAddrTypes = NULL;
    char **ppszIpAddrTypeList = NULL;
    size_t i = 0, ipAddrTypeCount = 0;
    NET_ADDR_TYPE ipAddrTypes = 0, addrType = 0;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = netmgrcli_find_cmdopt(pCmd, "interface", &pszIfname);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = netmgrcli_find_cmdopt(pCmd, "timeout", &pszTimeOut);
    BAIL_ON_CLI_ERROR(dwError);

    if ((ltimeout = strtol(pszTimeOut, &pszEnd, 10)) < 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = netmgrcli_find_cmdopt(pCmd, "addrtype", &pszAddrTypes);
    BAIL_ON_CLI_ERROR(dwError);

    dwError = netmgr_parse_comma_sep_tokens(pszAddrTypes,
                                            &dummy,
                                            &ipAddrTypeCount,
                                            &ppszIpAddrTypeList);
    BAIL_ON_PMD_ERROR(dwError);

    for (i = 0; i < ipAddrTypeCount; i++)
    {
        addrType = 0;
        dwError = get_ip_addrtype(ppszIpAddrTypeList[i], &addrType);
        BAIL_ON_PMD_ERROR(dwError);
        ipAddrTypes |= addrType;
    }

    dwError = netmgr_client_wait_for_ip(hPMD,
                                        pszIfname,
                                        (uint32_t)ltimeout,
                                        ipAddrTypes);
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    /* Free allocated memory */
    for (i = 0; i < ipAddrTypeCount; i++)
    {
        PMD_SAFE_FREE_MEMORY(ppszIpAddrTypeList[i]);
    }
    PMD_SAFE_FREE_MEMORY(ppszIpAddrTypeList);
    return dwError;

error:
    goto cleanup;;
}

static uint32_t
cmd_err_info(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0, dwErrCode = 0;
    char *pszErrCode = NULL, *pszEnd = NULL, *pszErrInfo = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    dwError = netmgrcli_find_cmdopt(pCmd, "errcode", &pszErrCode);
    BAIL_ON_CLI_ERROR(dwError);

    dwErrCode = strtol(pszErrCode, &pszEnd, 10);

    dwError = errno;
    BAIL_ON_CLI_ERROR(dwError);

    dwError = netmgr_client_get_error_info(hPMD, dwErrCode, &pszErrInfo);
    BAIL_ON_PMD_ERROR(dwError);
    if (pszErrInfo == NULL)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fprintf(stdout, "ErrorInfo: %s\n", pszErrInfo);

cleanup:
    return dwError;
error:
    goto cleanup;
}

static uint32_t
cmd_net_info(
    PPMDHANDLE hPMD,
    PNETMGR_CMD pCmd)
{
    uint32_t dwError = 0;
    char *pszObjectName = NULL, *pszParamName = NULL, *pszParamValue = NULL;

    if(!hPMD || !pCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_CLI_ERROR(dwError);
    }

    netmgrcli_find_cmdopt(pCmd, "objectname", &pszObjectName);

    switch (pCmd->op)
    {
        case OP_SET:
            dwError = netmgrcli_find_cmdopt(pCmd, "paramname", &pszParamName);
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgrcli_find_cmdopt(pCmd, "paramvalue", &pszParamValue);
            if (dwError == ENOENT)
            {
                dwError = 0;
            }
            BAIL_ON_CLI_ERROR(dwError);

            if (pszParamName != NULL)
            {
                dwError = netmgr_client_set_network_param(hPMD,
                                                          pszObjectName,
                                                          pszParamName,
                                                          pszParamValue);
                pszParamValue = NULL;
                BAIL_ON_CLI_ERROR(dwError);
            }
            break;

        case OP_GET:
            dwError = netmgrcli_find_cmdopt(pCmd, "paramname", &pszParamName);
            BAIL_ON_CLI_ERROR(dwError);

            dwError = netmgr_client_get_network_param(hPMD,
                                                      pszObjectName,
                                                      pszParamName,
                                                      &pszParamValue);
            BAIL_ON_CLI_ERROR(dwError);

            fprintf(stdout, "ParamName: %s, ParamValue: %s\n", pszParamName,
                    pszParamValue);
            break;

        default:
            dwError = EINVAL;
    }
    BAIL_ON_CLI_ERROR(dwError);

cleanup:
    PMD_CLI_SAFE_FREE_MEMORY(pszParamValue);
    return dwError;
error:
    goto cleanup;
}


typedef struct _NETMGR_CLI_HANDLER
{
    CMD_ID id;
    uint32_t (*pFnCmd)(PPMDHANDLE, PNETMGR_CMD);
} NETMGR_CLI_HANDLER, *PNETMGR_CLI_HANDLER;

NETMGR_CLI_HANDLER cmdHandler[] =
{
    { CMD_LINK_INFO,           cmd_link_info       },
    { CMD_IP4_ADDRESS,         cmd_ip4_address     },
    { CMD_IP6_ADDRESS,         cmd_ip6_address     },
    { CMD_IP_ROUTE,            cmd_ip_route        },
    { CMD_DNS_SERVERS,         cmd_dns_servers     },
    { CMD_DNS_DOMAINS,         cmd_dns_domains     },
    { CMD_DHCP_DUID,           cmd_dhcp_duid       },
    { CMD_IF_IAID,             cmd_if_iaid         },
    { CMD_NTP_SERVERS,         cmd_ntp_servers     },
    { CMD_HOSTNAME,            cmd_hostname        },
    { CMD_WAIT_FOR_LINK,       cmd_wait_for_link   },
    { CMD_WAIT_FOR_IP,         cmd_wait_for_ip     },
    { CMD_ERR_INFO,            cmd_err_info        },
    { CMD_NET_INFO,            cmd_net_info        },
};

uint32_t
netmgr_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs)
{
    uint32_t dwError = 0;
    size_t i, cmdCount = sizeof(cmdHandler)/sizeof(NETMGR_CLI_HANDLER);
    PPMDHANDLE hPMD = NULL;
    PNETMGR_CMD pCmd = NULL;
    char *arg1;

    arg1 = (char *)argv[1];
    if (argc > 2)
    {
        strcpy(arg1, argv[2]);
    }
    dwError = netmgrcli_parse_cmdline(argc, (char **)argv, &pCmd);
    BAIL_ON_CLI_ERROR(dwError);

    for (i = 0; i < cmdCount; i++)
    {
        if (pCmd->id == cmdHandler[i].id)
        {
            dwError = rpc_open(
                              "net",
                              pMainArgs->pszServer,
                              pMainArgs->pszUser,
                              pMainArgs->pszDomain,
                              pMainArgs->pszPass,
                              pMainArgs->pszSpn,
                              &hPMD);
            BAIL_ON_CLI_ERROR(dwError);

            dwError = cmdHandler[i].pFnCmd(hPMD, pCmd);
            BAIL_ON_CLI_ERROR(dwError);
            break;
        }
    }

cleanup:
    rpc_free_handle(hPMD);
    if(pCmd)
    {
        netmgrcli_free_cmd(pCmd);
    }
    return dwError;

error:
    if(netmgr_print_error(hPMD, dwError) == 0)
    {
        dwError = ERROR_PMD_FAIL;//already handled
    }
    goto cleanup;
}

uint32_t
netmgr_print_error(
    PPMDHANDLE hPMD,
    uint32_t dwErrorCode
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;

    if(dwErrorCode >= ERROR_PMD_NET_BASE)
    {
        if(!hPMD)
        {
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_CLI_ERROR(dwError);
        }
        dwError = netmgr_client_get_error_info(hPMD, dwErrorCode, &pszError);
        BAIL_ON_CLI_ERROR(dwError);
    }
    else
    {
        dwError = dwErrorCode;
        goto cleanup;//let the super main handle
    }
    printf("Error(%d) : %s\n", dwErrorCode, pszError);

cleanup:
    PMD_CLI_SAFE_FREE_MEMORY(pszError);
    return dwError;

error:
    printf(
        "Retrieving error string for %d failed with %d\n",
        dwErrorCode,
        dwError);
    goto cleanup;
}
