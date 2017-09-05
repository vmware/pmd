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

#define MAX_HTTP_DATA_LEN 4094
#define AUTHORIZATION "Authorization"
#define AUTH_BASIC "Basic "
#define AUTH_NEGOTIATE "Negotiate "
#define AUTH_BEARER "Bearer "
#define JAVELIN_OAUTH_AUD "rs_javelin_server"
#define LW_ADMIN_GROUP_NAME "Administrators"

typedef enum
{
    HTTP_FORBIDDEN = 403
}HTTP_STATUS_CODE;

#define RPC_PRIVSEPD_IF "privsepd"
