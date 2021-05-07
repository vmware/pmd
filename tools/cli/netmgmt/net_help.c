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
            "  status                       Show system status\n"
            "  show                         [LINK] Show link status.\n"
            "  set-mtu                      [LINK] [MTU NUMBER] Configures Link MTU.\n"
            "  set-mac                      [LINK] [MAC] Configures Link MAC address.\n"
            "  set-link-mode                [LINK] [MODE BOOLEAN] Configures Link managed by networkd.\n"
            "  set-dhcp-mode                [LINK] [DHCP-MODE {yes|no|ipv4|ipv6}] Configures Link DHCP setting.\n"
            "  set-dhcp4-client-identifier  [LINK] [IDENTIFIER {mac|duid|duid-only} Configures Link DHCPv4 identifier.\n"
            "  set-dhcp-iaid                [LINK] [IAID] Configures the DHCP Identity Association Identifier (IAID) for the interface, a 32-bit unsigned integer.\n"
            "  set-dhcp-duid                [LINK | system] [DUID {link-layer-time|vendor|link-layer|uuid}] [RAWDATA] Sets the DHCP Client.\n"
            "                                      Specifies how the DUID should be generated and [RAWDATA] to overides the global DUIDRawData.\n"
            "  set-link-state               [LINK] [STATE {up|down}] Configures Link State.\n"
            "  add-link-address             [LINK] address [ADDRESS] peer [ADDRESS]] label [NUMBER] pref-lifetime [{forever|infinity|0}] scope {global|link|host|NUMBER}]\n"
            "                                      dad [DAD {none|ipv4|ipv6|both}] prefix-route [PREFIXROUTE BOOLEAN] Configures Link Address.\n"
            "  delete-link-address          [LINK] Removes Address from Link.\n"
            "  add-default-gateway          [LINK] gw [GATEWAY ADDRESS] onlink [ONLINK BOOLEAN] Configures Link Default Gateway.\n"
            "  delete-gateway               [LINK] Removes Gateway from Link.\n"
            "  add-route                    [LINK] gw [GATEWAY ADDRESS] dest [DESTINATION ADDRESS] src [SOURCE ADDRESS] pref-src [PREFFREDSOURCE ADDRESS]\n"
            "                                      metric [METRIC NUMBER] scope [SCOPE {global|site|link|host|nowhere}] mtu [MTU NUMBER]\n"
            "                                      table [TABLE {default|main|local|NUMBER}] proto [PROTOCOL {boot|static|ra|dhcp|NUMBER}]\n"
            "                                      type [TYPE {unicast|local|broadcast|anycast|multicast|blackhole|unreachable|prohibit|throw|nat|resolve}]\n"
            "                                      ipv6-pref [IPV6PREFERENCE {low|medium|high}] onlink [{ONLINK BOOLEN}] Configures Link route.\n"
            "  delete-route                 [LINK] Removes route from Link\n"
            "  add-additional-gw            [LINK] address [ADDRESS] route [ROUTE address] gw [GW address] table [TABLE routing policy table NUMBER] Configures additional\n"
            "                                      gateway for another NIC with routing policy rules.\n"
            "  add-rule                     [LINK] table [TABLE NUMBER] from [ADDRESS] to [ADDRESS] oif [LINK] iif [LINK] priority [NUMBER] tos [NUMBER]\n"
            "                                      Configures Routing Policy Rule.\n"
            "  remove-rule                  [LINK] Removes Routing Policy Rule.\n"
            "  set-hostname                 [HOSTNAME] Configures hostname.\n"
            "  add-dns                      [LINK|global|system] [ADDRESS] Configures Link or global DNS servers.\n"
            "  add-domain                   [LINK|global|system] [DOMAIN] Configures Link or global Domain.\n"
            "  revert-resolve-link          [LINK] Flushes all DNS server and Domain settings of the link.\n"
            "  set-link-local-address       [LINK] [LinkLocalAddressing BOOLEAN] Configures Link link-local address auto configuration.\n"
            "  set-ipv4ll-route             [LINK] [IPv4LLRoute BOOLEAN] Configures the route needed for non-IPv4LL hosts to communicate.\n"
            "                                      with IPv4LL-only hosts.\n"
            "  set-llmnr                    [LINK] [LLMNR BOOLEAN] Configures Link Local Multicast Name Resolution.\n"
            "  set-multicast-dns            [LINK] [MulticastDNS BOOLEAN] Configures Link Multicast DNS.\n"
            "  set-lldp                     [LINK] [LLDP BOOLEAN] Configures Link Ethernet LLDP packet reception.\n"
            "  set-emit-lldp                [LINK] [EmitLLDP BOOLEAN] Configures Link Ethernet LLDP packet emission.\n"
            "  set-ipforward                [LINK] [IPForward BOOLEAN] Configures Link IP packet forwarding for the system.\n"
            "  set-ipv6acceptra             [LINK] [IPv6AcceptRA BOOLEAN] Configures Link IPv6 Router Advertisement (RA) reception support for the interface.\n"
            "  set-ipv6mtu                  [LINK] [MTU NUMBER] Configures IPv6 maximum transmission unit (MTU).\n"
            "  set-ipmasquerade             [LINK] [IPMasquerade BOOLEAN] Configures IP masquerading for the network interface.\n"
            "  set-ipv4proxyarp             [LINK] [IPv4ProxyARP BOOLEAN] Configures Link proxy ARP for IPv4.\n"
            "  set-ipv6proxyndp             [LINK] [IPv6ProxyNDP BOOLEAN] Configures Link proxy NDP for IPv6.\n"
            "  set-conf-without-carrier     [LINK] [ConfigureWithoutCarrier BOOLEAN] Allows networkd to configure link even if it has no carrier.\n"
            "  set-dhcp4-use-dns            [LINK] [UseDNS BOOLEAN] Configures Link DHCP4 Use DNS.\n"
            "  set-dhcp4-use-domains        [LINK] [UseDomains BOOLEAN] Configures Link DHCP4 Use Domains.\n"
            "  set-dhcp4-use-mtu            [LINK] [UseMTU BOOLEAN] Configures Link DHCP4 Use MTU.\n"
            "  set-dhcp4-use-ntp            [LINK] [UseNTP BOOLEAN] Configures Link DHCP4 Use NTP.\n"
            "  set-dhcp4-use-dns            [LINK] [UseDNS BOOLEAN] Configures Link DHCP4 Use DNS.\n"
            "  set-dhcp6-use-dns            [LINK] [UseDNS BOOLEAN] Configures Link DHCP6 Use DNS.\n"
            "  set-dhcp6-use-ntp            [LINK] [UseNTP BOOLEAN] Configures Link DHCP6 Use NTP.\n"
            "  add-ntp                      [LINK] [NTP] Add Link NTP server address. This option may be specified more than once.\n"
            "                                      This setting is read by systemd-timesyncd.service(8).\n"
            "  set-ntp                      [LINK] [NTP] Set Link NTP server address. This option may be specified more than once.\n"
            "                                      This setting is read by systemd-timesyncd.service(8).\n"
            "  delete-ntp                   [LINK] Delete Link NTP server addresses.\n"
            "                                      This setting is read by systemd-timesyncd.service(8)\n"
            "                                      This setting is read by systemd-timesyncd.service(8).\n"
            "  add-dhcpv4-server            [LINK] pool-offset [PoolOffset NUMBER] pool-size [PoolSize NUMBER] default-lease-time [DefaultLeaseTimeSec NUMBER]\n"
            "                                      max-lease-time [MaxLeaseTimeSec NUMBER] emit-dns [EmitDNS BOOLEAN]\n"
            "                                      dns [DNS ADDRESS] emit-ntp [EmitNTP BOOLEAN] ntp [NTP ADDRESS]\n"
            "                                      emit-router [EmitRouter BOOLEAN] Configures DHCPv4 server.\n"
            "  remove-dhcpv4-server         [LINK] Removes DHCPv4 server.\n"
            "  add-ipv6ra                   [LINK] prefix [Prefix ADDRESS] pref-lifetime [PreferredLifetimeSec NUMBER] valid-lifetime [ValidLifetimeSec NUMBER]\n"
            "                                      assign [Assign BOOLEAN] managed [Managed BOOLEAN]\n"
            "                                      other [Other BOOLEAN] dns [DNS ADDRESS] emit-dns [EmitDNS BOOLEAN]\n"
            "                                      domain [DOMAIN ADDRESS] emit-domain [EmitDOMAIN BOOLEAN]\n"
            "                                      router-pref [RouterPreference {low | med | high}]\n"
            "                                      route [Prefix ADDRESS] route-lifetime [LifetimeSec NUMBER] Configures IPv6 Router Advertisement.\n"
            "  remove-ipv6ra                [LINK] Removes Ipv6 Router Advertisement.\n"
            "  disable-ipv6                 [LINK] Disables IPv6 on the link.\n"
            "  enable-ipv6                  [LINK] Enables IPv6 on the link.\n"
            "  create-vlan                  [VLAN name] dev [LINK MASTER] id [ID INTEGER] proto [PROTOCOL {802.1q|802.1ad}] Creates vlan netdev and network file\n"
            "  create-bridge                [BRIDGE name] [LINK] [LINK] ... Creates bridge netdev and sets master to device\n"
            "  create-bond                  [BOND name] mode [MODE {balance-rr|active-backup|balance-xor|broadcast|802.3ad|balance-tlb|balance-alb}]\n"
            "                                      [LINK] [LINK] ... Creates bond netdev and sets master to device\n"
            "  create-vxlan                 [VXLAN name] [dev LINK] vni [INTEGER] [local ADDRESS] [remote ADDRESS] [port PORT] [independent BOOLEAN].\n"
            "                                      Creates vxlan VXLAN (Virtual eXtensible Local Area Network) tunneling.\n"
            "  create-macvlan               [MACVLAN name] dev [LINK] mode [MODE {private|vepa|bridge|passthru|source}] Creates macvlan virtualized bridged networking.\n"
            "  create-macvtap               [MACVTAP name] dev [LINK] mode [MODE {private|vepa|bridge|passthru|source}] Creates macvtap virtualized bridged networking.\n"
            "  create-ipvlan                [IPVLAN name] dev [LINK] mode [MODE {l2|l3|l3s}] Creates ipvlan, virtual LAN, separates broadcast domains by adding tags to network\n"
            "                                      packet.\n"
            "  create-ipvtap                [IPVTAP name] dev [LINK] mode [MODE {l2|l3|l3s}] Create ipvtap.\n"
            "  create-vrf                   [VRF name] table [INTEGER}] Creates Virtual routing and forwarding (VRF).\n"
            "  create-veth                  [VETH name] peer [PEER name}] Creates virtual Ethernet devices\n"
            "  create-ipip                  [IPIP name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates ipip tunnel.\n"
            "  create-sit                   [SIT name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates sit tunnel.\n"
            "  create-vti                   [VTI name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates vti tunnel.\n"
            "  create-gre                   [GRE name] [dev LINK] local [ADDRESS] remote [ADDRESS] [independent BOOLEAN] Creates gre tunnel.\n"
            "  create-wg                    [WIREGUARD name] private-key [PRIVATEKEY] listen-port [PORT INTEGER] public-key [PUBLICKEY] preshared-key [PRESHAREDKEY]\n"
            "                                      allowed-ips [IP,IP ...] endpoint [IP:PORT] Creates a wireguard tunnel.\n"
            "  reload                       Reload .network and .netdev files.\n"
            "  reconfigure                  [LINK] Reconfigure Link.\n"
            "  set-proxy                    [enable {BOOLEAN}] [http|https|ftp|gopher|socks|socks5|noproxy] [CONFIGURATION | none] Configure proxy.\n"
            "  add-nft-table                [FAMILY {ipv4|ipv6|ip}] [TABLE] adds a new table.\n"
            "  get-nft-tables               [FAMILY {ipv4|ipv6|ip}] [TABLE] shows nftable's tables.\n"
            "  delete-nft-table             [FAMILY {ipv4|ipv6|ip}] [TABLE] deletes a existing nftable's table.\n"
            "  add-nft-chain                [FAMILY {ipv4|ip}] [TABLE] [CHAIN] adds a new nftable's chain.\n"
            "  get-nft-chains               [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] shows nftable's chains.\n"
            "  delete-nft-chain             [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] deletes a nftable's chain from table\n"
            "  add-nft-rule                 [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] [PROTOCOL { tcp|udp}] [SOURCE PORT/DESTINATION PORT {sport|dport}]\n"
            "                                      [PORT] [ACTION {accept | drop}] configures a nft rule for a port.\n"
            "  get-nft-rules                [TABLE] shows nftable's rules.\n"
            "  delete-nft-rule              [FAMILY {ipv4|ipv6|ip}] [TABLE] [CHAIN] [HANDLE] deletes a nftable's rule from table\n"
            "  nft-run                      runs a nft command. See man NFT(8)\n"
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
            "  get-dhcp4-client-identifier  [LINK] Get Link DHCP4 Client Identifier.\n"

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
    {
        return "n/a";
    }

    if ((size_t) id >= ELEMENTSOF(net_dhcp_modes))
    {
        return NULL;
    }

    return net_dhcp_modes[id];
}

uint32_t
net_cli_convert_json_string(
    const char *pszJsonString,
    char **ppszJsonStringExt
    )
{
    uint32_t dwError = 0;
    struct json_object *jobj = NULL;
    char *pszJsonStringExt = NULL;

    if (IsNullOrEmptyString(pszJsonString))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    jobj = json_tokener_parse(pszJsonString);
    if (!jobj)
    {
        dwError = ERROR_PMD_NET_ALLOCATE_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pszJsonStringExt = strdup(json_object_to_json_string_ext(jobj,
                            JSON_C_TO_STRING_NOSLASHESCAPE
                            | JSON_C_TO_STRING_SPACED
                            | JSON_C_TO_STRING_PRETTY));
    if (IsNullOrEmptyString(pszJsonStringExt))
    {
        dwError = ERROR_PMD_NET_ALLOCATE_FAIL;
        BAIL_ON_PMD_ERROR(dwError);
    }
    *ppszJsonStringExt = steal_pointer(pszJsonStringExt);

cleanup:
    return dwError;

error:
    PMDFreeMemory(pszJsonStringExt);
    if (ppszJsonStringExt)
    {
        *ppszJsonStringExt = NULL;
    }
    goto cleanup;
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
        { "status",                       WORD_ANY, WORD_ANY, false, ncmcli_get_system_status },
        { "show",                         1,        WORD_ANY, false, ncmcli_get_link_status },
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
        { "add-additional-gw",            9,        WORD_ANY, false, ncmcli_configure },
        { "add-rule",                     3,        WORD_ANY, false, ncmcli_configure },
        { "remove-rule",                  1,        WORD_ANY, false, ncmcli_configure },
        { "set-hostname",                 1,        WORD_ANY, false, ncmcli_configure },
        { "add-dns",                      2,        WORD_ANY, false, ncmcli_configure },
        { "add-domain",                   1,        WORD_ANY, false, ncmcli_configure },
        { "revert-resolve-link",          1,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv6mtu",                  2,        WORD_ANY, false, ncmcli_configure },
        { "set-link-local-address",       2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv4ll-route",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-llmnr",                    2,        WORD_ANY, false, ncmcli_configure },
        { "set-multicast-dns",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-lldp",                     2,        WORD_ANY, false, ncmcli_configure },
        { "set-emit-lldp",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipforward",                2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv6acceptra",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipmasquerade",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv4proxyarp",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-ipv6proxyndp",             2,        WORD_ANY, false, ncmcli_configure },
        { "set-conf-without-carrier",     2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-dns",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-domains",        2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-ntp",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-mtu",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-timezone",       2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp4-use-routes",         2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-dns",            2,        WORD_ANY, false, ncmcli_configure },
        { "set-dhcp6-use-ntp",            2,        WORD_ANY, false, ncmcli_configure },
        { "add-dhcpv4-server",            1,        WORD_ANY, false, ncmcli_configure },
        { "remove-dhcpv4-server",         1,        WORD_ANY, false, ncmcli_configure },
        { "add-ipv6ra",                   1,        WORD_ANY, false, ncmcli_configure },
        { "remove-ipv6ra",                1,        WORD_ANY, false, ncmcli_configure },
        { "add-ntp",                      2,        WORD_ANY, false, ncmcli_configure },
        { "set-ntp",                      2,        WORD_ANY, false, ncmcli_configure },
        { "delete-ntp",                   1,        WORD_ANY, false, ncmcli_configure },
        { "disable-ipv6",                 1,        WORD_ANY, false, ncmcli_configure },
        { "enable-ipv6",                  1,        WORD_ANY, false, ncmcli_configure },
        { "create-vlan",                  4,        WORD_ANY, false, ncmcli_configure },
        { "create-bridge",                2,        WORD_ANY, false, ncmcli_configure },
        { "create-bond",                  5,        WORD_ANY, false, ncmcli_configure },
        { "create-vxlan",                 2,        WORD_ANY, false, ncmcli_configure },
        { "create-macvlan",               5,        WORD_ANY, false, ncmcli_configure },
        { "create-macvtap",               5,        WORD_ANY, false, ncmcli_configure },
        { "create-ipvlan",                5,        WORD_ANY, false, ncmcli_configure },
        { "create-ipvtap",                5,        WORD_ANY, false, ncmcli_configure },
        { "create-vrf",                   3,        WORD_ANY, false, ncmcli_configure },
        { "create-veth",                  3,        WORD_ANY, false, ncmcli_configure },
        { "create-ipip",                  3,        WORD_ANY, false, ncmcli_configure },
        { "create-sit",                   3,        WORD_ANY, false, ncmcli_configure },
        { "create-gre",                   3,        WORD_ANY, false, ncmcli_configure },
        { "create-vti",                   3,        WORD_ANY, false, ncmcli_configure },
        { "create-wg",                    3,        WORD_ANY, false, ncmcli_configure },
        { "remove-netdev",                1,        WORD_ANY, false, ncmcli_configure },
        { "reload",                       WORD_ANY, WORD_ANY, false, ncmcli_configure },
        { "reconfigure",                  1,        WORD_ANY, false, ncmcli_configure },
        { "set-proxy",                    1,        WORD_ANY, false, ncmcli_configure },
        { "add-nft-table",                2,        WORD_ANY, false, ncmcli_configure },
        { "get-nft-tables",               2,        WORD_ANY, false, ncmcli_nft_get_tables },
        { "delete-nft-table",             2,        WORD_ANY, false, ncmcli_configure },
        { "add-nft-chain",                3,        WORD_ANY, false, ncmcli_configure },
        { "get-nft-chains",               3,        WORD_ANY, false, ncmcli_nft_get_chains },
        { "delete-nft-chain",             3,        WORD_ANY, false, ncmcli_configure },
        { "add-nft-rule",                 7,        WORD_ANY, false, ncmcli_configure },
        { "get-nft-rules",                1,        WORD_ANY, false, ncmcli_get_nft_rules },
        { "delete-nft-rule",              2,        WORD_ANY, false, ncmcli_configure },
        { "nft-run",                      WORD_ANY, WORD_ANY, false, ncmcli_configure },
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
        { "get-dhcp4-client-identifier",  1,        WORD_ANY, false, ncmcli_link_get_dhcp4_client_identifier },
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
