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

void
rolemgmt_cli_show_help(
    )
{
    printf("usage: pmd-cli [connection options] rolemgmt <command> [command options]\n");
    printf("\n");

    printf("List of Main Commands\n");
    printf("\n");

    printf("roles                     Show current roles.\n");
    printf("version                   Show version.\n");
    printf("help                         Display a helpful usage message\n");

    printf("roles --list (default)       Show available roles.\n");

    printf("roles\n"
           "  --prereqs\n"
           "  --name <rolename>          List prerequisites.\n");

    printf("roles\n"
           "  --status\n"
           "  --name <rolename>\n"
           "  --taskid <task uuid>       Show status of task.\n");

    printf("roles\n"
           "  --enable\n"
           "  --name <rolename>\n"
           "  --config <configfile>  Enable role.\n");

    printf("roles\n"
           "  --update\n"
           "  --name <rolename>\n"
           "  --config <configfile>  Update role.\n");

    printf("roles\n"
           "  --remove\n"
           "  --name <rolename>\n"
           "  --config <configfile>  Remove role.\n");

    printf("version                      Show version.\n");
}
