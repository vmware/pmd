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
net_show_help(
    )
{
    printf("usage: pmd-cli [connection options] net <command> [command options]\n");
    printf("\n");

    printf("List of Main Commands\n");
    printf("\n");

    printf("help                      Display a helpful usage message\n");
    printf("dns_servers               set/get dns servers\n");
    printf("set_iaid                  set iaid\n");
    printf("get_iaid                  get iaid\n");
    printf("set_duid                  set duid\n");
    printf("get_duid                  get duid\n");
}
