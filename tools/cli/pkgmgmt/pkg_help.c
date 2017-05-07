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
pkg_show_help(
    )
{
    printf("usage: pmd-cli [connection options] pkg <command> [command options]\n");
    printf("\n");

    printf("List of Main Commands\n");
    printf("\n");

    printf("help                      Display a helpful usage message\n");
    printf("count                     Display total count of packages in all repos including installed.\n");
    printf("distro-sync               Synchronize installed packages to the latest available versions.\n");
    printf("downgrade                 Downgrade specified package(s). Call with no params to downgrade all available.\n");
    printf("erase                     Remove specified package(s).\n");
    printf("info                      Display details about a package or group of packages\n");
    printf("install                   Install package(s). Update if an update is available.\n");
    printf("list                      List a package or groups of packages\n");
    printf("reinstall                 Re-Install package(s).\n");
    printf("repolist                  Display the configured software repositories\n");
    printf("update                    Update specified package(s). Call with no params to update all available.\n");
    printf("updateinfo                Display updateinfo on all enabled repositories\n");
    printf("serverinfo                Display server information such as type, compose server, hash etc.\n");
    printf("rpmostreesyncto           Sync this client to the given hash. Client should be an rpmostree client.\n");
}
