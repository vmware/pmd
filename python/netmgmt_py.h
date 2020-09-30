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

extern PyTypeObject netType;
/*
 * Error codes
 */
#define NM_BASE_ERROR                          4096U
#define NM_ERR_INVALID_PARAMETER               (NM_BASE_ERROR + 1)
#define NM_ERR_NOT_SUPPORTED                   (NM_BASE_ERROR + 2)
#define NM_ERR_OUT_OF_MEMORY                   (NM_BASE_ERROR + 3)
#define NM_ERR_VALUE_NOT_FOUND                 (NM_BASE_ERROR + 4)
#define NM_ERR_VALUE_EXISTS                    (NM_BASE_ERROR + 5)
#define NM_ERR_INVALID_INTERFACE               (NM_BASE_ERROR + 6)
#define NM_ERR_INVALID_ADDRESS                 (NM_BASE_ERROR + 7)
#define NM_ERR_INVALID_MODE                    (NM_BASE_ERROR + 8)
#define NM_ERR_BAD_CONFIG_FILE                 (NM_BASE_ERROR + 9)
#define NM_ERR_WRITE_FAILED                    (NM_BASE_ERROR + 10)
#define NM_ERR_TIME_OUT                        (NM_BASE_ERROR + 11)
#define NM_ERR_DHCP_TIME_OUT                   (NM_BASE_ERROR + 12)
#define NM_MAX_ERROR                           (NM_BASE_ERROR + 100)
