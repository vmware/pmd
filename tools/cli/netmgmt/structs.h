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

typedef uint32_t (*NetCommandRunFunction)(PPMDHANDLE hPMD, int argc, char **argv);

typedef struct Cli {
        const char *name;
        unsigned min_args, max_args;
        bool default_command;
        NetCommandRunFunction run;
} NetCli;

typedef struct CliManager {
        GHashTable *hash;
        NetCli *commands;
} NetCliManager;

typedef enum DHCPMode {
        DHCP_MODE_NO,
        DHCP_MODE_YES,
        DHCP_MODE_IPV4,
        DHCP_MODE_IPV6,
        _DHCP_MODE_MAX,
        _DHCP_MODE_INVALID = -1
} DHCPMode;

