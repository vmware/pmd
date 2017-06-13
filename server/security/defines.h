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

#pragma once

#define MAX_API_SECURITY_LINE_LENGTH 150000

#define BAIL_ON_NT_STATUS(ntStatus) \
    do {                                                           \
        if ((ntStatus) != STATUS_SUCCESS)                          \
        {                                                          \
            goto error;                                            \
        }                                                          \
    } while(0)

#define CHECK_RPC_ACCESS(hBinding, dwError)                        \
    do {                                                           \
        dwError = has_admin_access(hBinding);                      \
        if(dwError){                                               \
            fprintf(stderr, "RPC admin access fail: %s", __func__);\
            goto error;                                            \
        }                                                          \
        else {                                                     \
            fprintf(stderr, "RPC admin access allowed: %s", __func__);\
        }                                                          \
    } while(0)
