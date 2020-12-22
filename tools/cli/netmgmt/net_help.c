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
net_show_help(
    )
{
    printf("usage: %s [connection options] net <command> [command options]\n\n"
            "Query and control the netmanager subsystem.\n\n"
            "  -h --help                    Show this help message and exit\n"
            "  -v --version                 Show package version\n"
            "\nCommands:\n"
            "  set-mtu                      [LINK] [MTU] Set Link MTU\n"
            "  set-mac                      [LINK] [MAC] Set Link MAC\n"
            "  set-link-mode                [LINK] [MODE { yes | no | on | off | 1 | 0} ] Set Link managed by networkd\n"
            "  set-dhcp-mode                [LINK] [DHCP-MODE { yes | no | ipv4 | ipv6 } ] Set Link DHCP setting\n"
            "  set-dhcp4-client-identifier  [LINK] [IDENTIFIER { mac | duid | duid-only}\n"
            "  set-dhcp-iaid                [LINK] [IAID] Sets the DHCP Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.\n"
            "  set-dhcp-duid                [LINK | system] [DUID { link-layer-time | vendor | link-layer | uuid } ] [RAWDATA] Sets the DHCP Client\n"
            "                                      DUID type which specifies how the DUID should be generated and [RAWDATA] to overides the global DUIDRawData.\n"
            "  set-link-state               [LINK] [STATE { up | down } ] Set Link State\n"
            "  add-link-address             [LINK] [ADDRESS] [PEER] ] Add Link Address\n"
            "  delete-link-address          [LINK] Removes Address from Link\n"
            "  add-default-gateway          [LINK] [ADDRESS] onlink [ONLINK { yes | no | on | off | 1 | 0}] Add Link Default Gateway\n"
            "  delete-gateway               [LINK] Removes Gateway from Link\n"
            "  add-route                    [LINK] [ADDRESS] metric [METRIC { number }] Set Link route\n"
            "  delete-route                 [LINK] Removes route from Link\n"
            "  set-hostname                 [HOSTNAME] Sets hostname\n"
            "  add-dns                      [LINK | system] [ADDRESS] Set Link DNS servers\n"
            "  add-domain                   [LINK | system] [DOMAIN] Set Link DOMAIN \n"
            "  revert-resolve-link          [LINK] Flushes all DNS server and Domain settings of the link\n"
            "  set-link-local-address       [LINK] [LinkLocalAddressing { yes | no | on | off | 1 | 0}] Set Link link-local address autoconfiguration\n"
            "  set-ipv4ll-route             [LINK] [IPv4LLRoute { yes | no | on | off | 1 | 0}] Set the route needed for non-IPv4LL hosts to communicate\n"
            "                                      with IPv4LL-only hosts\n"
            "  set-llmnr                    [LINK] [LLMNR { yes | no | on | off | 1 | 0}] Set Link Link-Local Multicast Name Resolution\n"
            "  set-multicast-dns            [LINK] [MulticastDNS { yes | no | on | off | 1 | 0}] Set Link Multicast DNS\n"
            "  set-lldp                     [LINK] [LLDP { yes | no | on | off | 1 | 0}] Set Link Ethernet LLDP packet reception\n"
            "  set-emit-lldp                [LINK] [EmitLLDP { yes | no | on | off | 1 | 0}] Set Link Ethernet LLDP packet emission\n"
            "  set-ipforward                [LINK] [IPForward { yes | no | on | off | 1 | 0}] Set Link IP packet forwarding for the system\n"
            "  set-ipv6acceptra             [LINK] [IPv6AcceptRA { yes | no | on | off | 1 | 0}] Set Link IPv6 Router Advertisement (RA) reception support for the interface\n"
            "  set-ipmasquerade             [LINK] [IPMasquerade { yes | no | on | off | 1 | 0}] Set IP masquerading for the network interface\n"
            "  set-dhcp4-use-dns            [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use DNS\n"
            "  set-dhcp4-use-domains        [LINK] [UseDomains { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use DOMAINS\n"
            "  set-dhcp4-use-mtu            [LINK] [UseMTU { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use MTU\n"
            "  set-dhcp4-use-ntp            [LINK] [UseNTP { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use NTP\n"
            "  set-dhcp4-use-dns            [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP4 Use DNS\n"
            "  set-dhcp6-use-dns            [LINK] [UseDNS { yes | no | on | off | 1 | 0}] Set Link DHCP6 Use DNS\n"
            "  set-dhcp6-use-ntp            [LINK] [UseNTP { yes | no | on | off | 1 | 0}] Set Link DHCP6 Use NTP\n"
            "  add-ntp                      [LINK] [NTP] Add Link NTP server address. This option may be specified more than once.\n"
            "                                      This setting is read by systemd-timesyncd.service(8)\n"
            "  set-ntp                      [LINK] [NTP] Set Link NTP server address. This option may be specified more than once.\n"
            "                                      This setting is read by systemd-timesyncd.service(8)\n"
            "  delete-ntp                   [LINK] Delete Link NTP server addresses.\n"
            "                                      This setting is read by systemd-timesyncd.service(8)\n"
            "  disable-ipv6                 [LINK] Disables IPv6 on the interface.\n"
            "  enable-ipv6                  [LINK] Enables IPv6 on the interface.\n"
            "  reload                              Reload .network and .netdev files.\n"
            "  reconfigure                  [LINK] Reconfigure Link.\n"
            "  is-networkd-running                 Check if systemd-networkd is running or not. \n"
            "  get-hostname                        Gets hostname\n"
            "  get-dns-servers                     Gets DNS Servers\n"
            "  get-dns-domains                     Gets DNS Server DOMAINS\n"
            "  get-ntp                      [LINK] Get Link NTP server address\n"
            "  get-link-address             [LINK] Get Link Address\n"
            "  get-link-route               [LINK] Get Link route\n"
            "  get-dhcp-mode                [LINK] Get Link DHCP setting. DHCP-MODE { yes | no | ipv4 | ipv6 }\n"
            "  get-mac                      [LINK] Get Link MAC\n"
            "  get-mtu                      [LINK] Get Link MTU\n"
            "  get-dhcp-iaid                [LINK] Gets the DHCP Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.\n"

            , program_invocation_short_name
            );

    return 0;
}

/* TODO: Show precise error as returned by ncm */
uint32_t
net_print_error(
    uint32_t dwErrorCode
    )
{
    uint32_t dwError = 0;
    char* pszError = NULL;

    switch(dwErrorCode)
    {
        case ERROR_PMD_NET_ALLOCATE_FAIL:
            pszError = "Memory allocation failed!!";
            break;
        case ERROR_PMD_NET_CMD_FAIL:
            pszError = "network-config-manager command failed!!";
            break;
        case ERROR_PMD_NET_UNKNOWN_CLI_CMD:
            pszError = "Unknown CLI command!!";
            break;
        case ERROR_PMD_NET_TOO_FEW_ARGS:
            pszError = "Too few Arguments!!";
            break;
        case ERROR_PMD_NET_TOO_MANY_ARGS:
            pszError = "Too many Arguments!!";
            break;
        case ERROR_PMD_NET_UNSUPPORTED_CMD:
            pszError = "Unsupported command!!";
            break;
        default:
            dwError = dwErrorCode;
            /* let the super main handle */
            goto cleanup;
    }
    printf("Error(%d) : %s\n", dwErrorCode, pszError);

cleanup:
    return dwError;
}

static const char *const net_dhcp_modes[_DHCP_MODE_MAX] = {
    [DHCP_MODE_NO]   = "no",
    [DHCP_MODE_YES]  = "yes",
    [DHCP_MODE_IPV4] = "ipv4",
    [DHCP_MODE_IPV6] = "ipv6",
};

const char *
net_dhcp_modes_to_name(
    int id
    )
{
    if (id < 0)
        return "n/a";

    if ((size_t) id >= ELEMENTSOF(net_dhcp_modes))
        return NULL;

    return net_dhcp_modes[id];
}

uint32_t
net_cli_manager_new(
    NetCliManager **ppNetCliMgr
    )
{
    NetCliManager *pNetCliMgr = NULL;
    int i = 0;
    uint32_t dwError = 0;

    if (!ppNetCliMgr)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    static const NetCli cli_commands[] = {
        { "help",                         WORD_ANY, WORD_ANY, true,  net_show_help },
        { "version",                      WORD_ANY, WORD_ANY, false, ncmcli_get_version },
        { "set-mtu",                      2,        WORD_ANY, false, ncmcli_configure },
        { "set-mac",                      2,        WORD_ANY, false, ncmcli_configure },
        { "set-link-mode",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp-mode",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-client-identifier",  2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp-iaid",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp-duid",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-link-state",               2,        WORD_ANY, false, ncmcli_configure },
        { "add-link-address",             2,        WORD_ANY, false, ncmcli_configure },
        { "delete-link-address",          1,        WORD_ANY, false, ncmcli_configure },
        { "add-default-gateway",          2,        WORD_ANY, false, ncmcli_configure },
        { "delete-gateway",               1,        WORD_ANY, false, ncmcli_configure },
        { "add-route",                    2,        WORD_ANY, false, ncmcli_configure },
        { "delete-route",                 1,        WORD_ANY, false, ncmcli_configure },
        { "set-hostname",                 1,        WORD_ANY, false, ncmcli_configure },
        { "add-dns",                      2,        WORD_ANY, false, ncmcli_configure },
        { "add-domain",                   1,        WORD_ANY, false, ncmcli_configure },
        { "revert-resolve-link",          1,        WORD_ANY, false, ncmcli_configure },
        { "set-link-local-address",       2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv4ll-route",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-llmnr",                    2,        WORD_ANY, false, ncmcli_configure },
        { "set-multicast-dns",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-lldp",                     2,        WORD_ANY, false, ncmcli_configure },
        { "set-emit-lldp",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipforward",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv6acceptra",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipmasquerade",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-dns",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-domains",        2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-ntp",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-mtu",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-timezone",       2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-routes",         2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-dns",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-domains",        2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-ntp",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-mtu",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-timezone",       2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-routes",         2,        WORD_ANY, false, ncmcli_configure },
        { "add-ntp",                      2,        WORD_ANY, false, ncmcli_configure },
        { "set-ntp",                      2,        WORD_ANY, false, ncmcli_configure },
        { "delete-ntp",                   2,        WORD_ANY, false, ncmcli_configure },
        { "disable-ipv6",                 1,        WORD_ANY, false, ncmcli_configure },
        { "enable-ipv6",                  1,        WORD_ANY, false, ncmcli_configure },
        { "reload",                       WORD_ANY, WORD_ANY, false, ncmcli_configure },
        { "reconfigure",                  WORD_ANY, WORD_ANY, false, ncmcli_configure },
        { "is-networkd-running",          WORD_ANY, WORD_ANY, false, ncmcli_is_networkd_running },
        { "get-hostname",                 WORD_ANY, WORD_ANY, false, ncmcli_get_system_hostname },
        { "get-dns-servers",              WORD_ANY, WORD_ANY, false, ncmcli_get_dns_server },
        { "get-dns-domains",              WORD_ANY, WORD_ANY, false, ncmcli_get_dns_domains },
        { "get-ntp",                      1,        WORD_ANY, false, ncmcli_link_get_ntp },
        { "get-link-address",             1,        WORD_ANY, false, ncmcli_link_get_addresses },
        { "get-link-route",               1,        WORD_ANY, false, ncmcli_link_get_routes },
        { "get-dhcp-mode",                1,        WORD_ANY, false, ncmcli_link_get_dhcp_mode },
        { "get-mac",                      1,        WORD_ANY, false, ncmcli_link_get_mac_addr },
        { "get-mtu",                      1,        WORD_ANY, false, ncmcli_link_get_mtu },
        { "get-dhcp-iaid",                1,        WORD_ANY, false, ncmcli_link_get_dhcp_client_iaid },
        {}
    };

    dwError = PMDAllocateMemory(sizeof(NetCliManager *),
            (void **)&pNetCliMgr);
    BAIL_ON_PMD_ERROR(dwError);

    *pNetCliMgr = (NetCliManager) {
        .hash = g_hash_table_new(g_str_hash, g_str_equal),
            .commands = (NetCli *) cli_commands,
    };

    if (!pNetCliMgr->hash)
    {
        dwError = ERROR_PMD_NET_ALLOCATE_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }
    for (i = 0; cli_commands[i].name; i++)
    {
        if (!g_hash_table_insert(pNetCliMgr->hash, (gpointer *) cli_commands[i].name, (gpointer *) &cli_commands[i]));
    }

    *ppNetCliMgr = pNetCliMgr;
cleanup:
    return dwError;
error:
    if (ppNetCliMgr)
    {
        *ppNetCliMgr = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pNetCliMgr);
    goto cleanup;
}

void
net_cli_unrefp(
    NetCliManager **ppNetCliMgr
    )
{
    if (ppNetCliMgr && *ppNetCliMgr) {
        g_hash_table_unref((*ppNetCliMgr)->hash);
        PMD_SAFE_FREE_MEMORY(*ppNetCliMgr);
    }
}

static NetCli *
net_cli_get_command(
    const NetCliManager *pNetCliMgr,
    const char *pszCmd
    )
{
    uint32_t dwError = 0;
    NetCli *pNetCli = NULL;

    if (!pNetCliMgr || !pszCmd)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pNetCli = g_hash_table_lookup(pNetCliMgr->hash, pszCmd);
cleanup:
    return pNetCli;
error:
    goto cleanup;
}

uint32_t
net_cli_run_command(
    const NetCliManager *pNetCliMgr,
    PPMDHANDLE pHandle,
    int argc,
    char *argv[]
    )
{
    NetCli *pNetCmd = NULL;
    int remaining_argc = argc - 2;
    char *pszName = NULL;
    uint32_t dwError = 0;
    int i = 0;
    char c;
    static const struct option options[] = {
        { "help",       no_argument,       NULL, 'h' },
        { "version",    no_argument,       NULL, 'v' },
        { "servername", required_argument, NULL, 's' },
        { "user",       required_argument, NULL, 'u' },
        {}
    };

    if (!pNetCliMgr || !pHandle || !argv || (argc <= 0))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    optind = 0;
    while ((c = getopt_long(argc, argv, "s:u:hv", options, NULL)) >= 0)
    {
        switch (c)
        {
            case 'h':
                dwError = net_show_help();
                BAIL_ON_CLI_ERROR(dwError);
                goto cleanup;
            case 'v':
                pszName = "version";
                break;
            case 's':
                remaining_argc--;
                break;
            case 'u':
                remaining_argc--;
                break;
            default:
                dwError = ERROR_PMD_INVALID_PARAMETER;
                BAIL_ON_CLI_ERROR(dwError);
        }
    }

    argv += (optind + 1);

    if (!pszName)
    {
        pszName = argv[0];
    }
    /* run default if no command specified */
    if (!pszName)
    {
        for (i = 0; pNetCliMgr->commands[i].default_command; i++)
        {
            pNetCmd = pNetCliMgr->commands;
            if (strcmp(pNetCmd->name, "help"))
            {
                dwError = net_show_help();
            }
            else
            {
                remaining_argc = 1;
                dwError = pNetCmd->run(pHandle, remaining_argc, argv);
            }
            BAIL_ON_PMD_ERROR(dwError);
            goto cleanup;
        }
    }

    pNetCmd = net_cli_get_command(pNetCliMgr, pszName);
    if (!pNetCmd)
    {
        dwError = ERROR_PMD_NET_UNKNOWN_CLI_CMD;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pNetCmd->min_args != WORD_ANY && (unsigned) remaining_argc <= pNetCmd->min_args)
    {
        dwError = ERROR_PMD_NET_TOO_FEW_ARGS;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pNetCmd->max_args != WORD_ANY && (unsigned) remaining_argc > pNetCmd->max_args)
    {
        dwError = ERROR_PMD_NET_TOO_MANY_ARGS;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = pNetCmd->run(pHandle, remaining_argc, argv);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;
error:
    goto cleanup;
}
