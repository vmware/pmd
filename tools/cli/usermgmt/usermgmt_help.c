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
usermgmt_cli_show_help(
    )
{
    printf("usage: pmd-cli [connection options] usermgmt <command> [command options]\n");
    printf("\n");

    printf("List of Main Commands\n");
    printf("\n");

    printf("help                      Display a helpful usage message\n");
    printf("users                     List all users.\n");
    printf("useradd                   Add user.\n");
    printf("userdel                   Delete user.\n");
    printf("userid                    Find id of user by name. Doubles as an exists check.\n");
    printf("groups                    List all groups.\n");
    printf("groupadd                  Add group.\n");
    printf("groupdel                  Delete group.\n");
    printf("groupid                   Find id of group by name. Doubles as an exists check.\n");
    printf("version                   Show version.\n");
}
