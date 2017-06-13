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
demo_show_help(
    )
{
    printf("usage: pmd-cli [connection options] demo <command> [command options]\n");
    printf("\n");

    printf("List of Main Commands\n");
    printf("\n");

    printf("help                      Display a helpful usage message\n");
    printf("isprime                   check for primeness in given number.\n");
    printf("primes                    prints n primes from a given number.\n");
    printf("fav                       sets gets removes or replaces favorite primes at server.\n");
}
