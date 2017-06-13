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

void
show_usage(
    )
{
    printf("You need to specify a component and a command\n");
    show_help();
}

void
show_help(
    )
{
    printf("usage: pmd-cli [connection/auth options] <component> <command> [command options]\n");
    printf("\n");
    printf("For local connections, use: pmd-cli <component> <cmd> <options>.\n");
    printf("Current logged in user permissions will apply when executing commands.\n");
    printf("This is the same as specifying --%s localhost.\n", OPT_SERVERNAME);
    printf("For remote servers, use one of 3 methods mentioned below. Password is never sent out to the remote in any of the below auth scenarios.\n");
    printf("When --%s is specified, you will be prompted for password.\n", OPT_USERNAME);
    printf("1. System user.\n");
    printf("   pmd-cli --%s <server> --%s <user>\n",
    OPT_SERVERNAME, OPT_USERNAME);
    printf("2. Lightwave user (pmd server must be joined or should be part of embedded lightwave)\n");
    printf("   pmd-cli --%s <server> --%s <user> --%s <lightwave domain>\n",
    OPT_SERVERNAME, OPT_USERNAME, OPT_DOMAINNAME);
    printf("3. Kerberos spn (client must successfully run kinit before using this method)\n");
    printf("   pmd-cli --%s <server> --%s <service principal name>\n",
    OPT_SERVERNAME, OPT_SPN);
}

void
show_no_such_cmd(
    const char* pszCmd
    )
{
    printf("No such command: %s. Please use pmd-cli --help\n", pszCmd);
}

void
show_no_such_option(
    const char* pszOption
    )
{
    printf("No such option: %s. Please use pmd-cli --help\n", pszOption);
}

uint32_t
help_cmd(
    PPMDHANDLE hPMD,
    PPMD_CMD_ARGS pCmdArgs
    )
{
    show_help();
    return 0;
}
