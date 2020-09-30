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


#pragma once

#define WORD_ANY ((unsigned) -1)
#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

uint32_t
net_cli_manager_new(
    NetCliManager **ppNetCliMgr
    );

void
net_cli_unrefp(
    NetCliManager **ppNetCliMgr
    );

uint32_t
net_cli_run_command(
    const NetCliManager *pNetCliMgr,
    PPMDHANDLE pHandle,
    int argc,
    char *argv[]
    );

uint32_t
net_show_help(
    );

uint32_t
net_print_error(
    uint32_t dwErrorCode
    );

const char *
net_dhcp_modes_to_name(
    int id
    );

uint32_t
ncmcli_configure(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_get_version(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_is_networkd_running(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_get_system_hostname(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_addresses(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_routes(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_get_dns_server(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_get_dns_domains(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_ntp(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_dhcp_mode(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_mac_addr(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_dhcp_client_iaid(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);

uint32_t
ncmcli_link_get_mtu(
    PPMDHANDLE hPMD,
    int argc,
    char *argv[]
);
