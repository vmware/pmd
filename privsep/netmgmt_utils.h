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

#include <glib.h>

typedef int (*NetmgmtCommandRunFunction)(int argc, char **argv);

typedef struct Cli {
    const char *name;
    NetmgmtCommandRunFunction run;
} NetmgmtCli;

typedef struct CliManager {
    GHashTable *hash;
    NetmgmtCli *commands;
} NetmgmtCliManager;

uint32_t
netmgmt_cli_manager_new(
    NetmgmtCliManager **pNetCliMgr
    );

void
netmgmt_cli_unrefp(
    NetmgmtCliManager **pNetCliMgr
    );

uint32_t
netmgmt_cli_run_command(
    const NetmgmtCliManager *pNetCliMgr,
    int argc,
    char *argv[]
    );
