/*
 * Copyright © 2020 VMware, Inc.  All Rights Reserved.
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
netmgmt_cli_manager_new(
    NetmgmtCliManager **ppNetCliMgr
    )
{
    NetmgmtCliManager *pNetCliMgr = NULL;
    uint32_t i = 0;
    uint32_t dwError = 0;

    if (!ppNetCliMgr)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    static const NetmgmtCli cli_commands[] = {
        { "set-mtu",                      ncm_link_set_mtu },
        { "set-mac",                      ncm_link_set_mac },
        { "set-link-mode",                ncm_link_set_mode },
        { "set-dhcp-mode",                ncm_link_set_dhcp_mode },
        { "set-dhcp4-client-identifier",  ncm_link_set_dhcp4_client_identifier},
        { "set-dhcp-iaid",                ncm_link_set_dhcp_client_iaid},
        { "set-dhcp-duid",                ncm_link_set_dhcp_client_duid},
        { "set-link-state",               ncm_link_update_state },
        { "add-link-address",             ncm_link_add_address },
        { "delete-link-address",          ncm_link_delete_address },
        { "add-default-gateway",          ncm_link_add_default_gateway },
        { "delete-gateway",               ncm_link_delete_gateway_or_route },
        { "add-route",                    ncm_link_add_route },
        { "delete-route",                 ncm_link_delete_gateway_or_route },
        { "set-hostname",                 ncm_set_system_hostname },
        { "add-dns",                      ncm_add_dns_server },
        { "add-domain",                   ncm_add_dns_domains },
        { "show-domains",                 ncm_show_dns_server_domains },
        { "revert-resolve-link",          ncm_revert_resolve_link },
        { "set-link-local-address",       ncm_link_set_network_section_bool },
        { "set-ipv4ll-route",             ncm_link_set_network_section_bool },
        { "set-llmnr",                    ncm_link_set_network_section_bool },
        { "set-multicast-dns",            ncm_link_set_network_section_bool },
        { "set-lldp",                     ncm_link_set_network_section_bool },
        { "set-emit-lldp",                ncm_link_set_network_section_bool },
        { "set-ipforward",                ncm_link_set_network_section_bool },
        { "set-ipv6acceptra",             ncm_link_set_network_section_bool },
        { "set-ipmasquerade",             ncm_link_set_network_section_bool },
        { "set-dhcp4-use-dns",            ncm_link_set_dhcp4_section },
        { "set-dhcp4-use-domains",        ncm_link_set_dhcp4_section },
        { "set-dhcp4-use-ntp",            ncm_link_set_dhcp4_section },
        { "set-dhcp4-use-mtu",            ncm_link_set_dhcp4_section },
        { "set-dhcp4-use-timezone",       ncm_link_set_dhcp4_section },
        { "set-dhcp4-use-routes",         ncm_link_set_dhcp4_section },
        { "set-dhcp6-use-dns",            ncm_link_set_dhcp6_section },
        { "set-dhcp6-use-domains",        ncm_link_set_dhcp6_section },
        { "set-dhcp6-use-ntp",            ncm_link_set_dhcp6_section },
        { "set-dhcp6-use-mtu",            ncm_link_set_dhcp6_section },
        { "set-dhcp6-use-timezone",       ncm_link_set_dhcp6_section },
        { "set-dhcp6-use-routes",         ncm_link_set_dhcp6_section },
        { "add-ntp",                      ncm_link_add_ntp },
        { "set-ntp",                      ncm_link_add_ntp },
        { "delete-ntp",                   ncm_link_delete_ntp },
        { "disable-ipv6",                 ncm_link_enable_ipv6 },
        { "enable-ipv6",                  ncm_link_enable_ipv6 },
        { "reload",                       ncm_network_reload },
        { "reconfigure",                  ncm_link_reconfigure },
        {}
    };

    dwError = PMDAllocateMemory(sizeof(NetmgmtCliManager *),
            (void **)&pNetCliMgr);
    BAIL_ON_PMD_ERROR(dwError);

    *pNetCliMgr = (NetmgmtCliManager) {
        .hash = g_hash_table_new(g_str_hash, g_str_equal),
            .commands = (NetmgmtCli *) cli_commands,
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
netmgmt_cli_unrefp(
    NetmgmtCliManager **ppNetCliMgr
    )
{
    if (ppNetCliMgr && *ppNetCliMgr)
    {
        g_hash_table_unref((*ppNetCliMgr)->hash);
        PMD_SAFE_FREE_MEMORY(*ppNetCliMgr);
    }
}

static NetmgmtCli *
netmgmt_cli_get_command(
    const NetmgmtCliManager *pNetCliMgr,
    const char *pszCmdName
    )
{
    uint32_t dwError = 0;
    NetmgmtCli *pNetCli = NULL;

    if (!pNetCliMgr || !pszCmdName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pNetCli = g_hash_table_lookup(pNetCliMgr->hash, pszCmdName);
cleanup:
    return pNetCli;
error:
    goto cleanup;
}

uint32_t
netmgmt_cli_run_command(
    const NetmgmtCliManager *pNetCliMgr,
    int argc,
    char *argv[]
    )
{
    NetmgmtCli *pNetCommand = NULL;
    uint32_t dwError = 0;

    if (!pNetCliMgr || !argv || (argc == 0))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pNetCommand = netmgmt_cli_get_command(pNetCliMgr, argv[0]);
    if (!pNetCommand) {
        dwError = ERROR_PMD_NET_UNKNOWN_CLI_CMD;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pNetCommand->run(argc, argv) < 0)
    {
        dwError = ERROR_PMD_NET_CMD_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }
cleanup:
    return dwError;
error:
    goto cleanup;
}
