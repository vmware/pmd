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

typedef struct _PMDHANDLE_* PPMDHANDLE;

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

#define IsNullOrEmptyString(str) (!(str) || !(*str))

#define BAIL_ON_PMD_SYSTEM_ERROR(dwError) \
    do {                                                           \
        if (dwError)                                               \
        {                                                          \
            dwError = ERROR_PMD_SYSTEM_BASE + dwError;             \
            goto error;                                            \
        }                                                          \
    } while(0)

#define PKG_CONFIG_FILE_NAME "/etc/tdnf/tdnf.conf"
#define PMD_CONFIG_FILE_NAME "/etc/pmd/pmd.conf"
#define PMD_CONFIG_MAIN_GROUP "main"
#define PMD_CONFIG_REST_GROUP "rest-server"
#define PMD_CONFIG_PRIVSEP_GROUP "privsep"

#define PMD_CONFIG_KEY_REST_ENABLED "enabled"
#define PMD_CONFIG_KEY_REST_PORT    "port"
#define PMD_CONFIG_KEY_REST_APISPEC "apispec"

#define PMD_CONFIG_KEY_SERVERTYPE "servertype"
#define PMD_CONFIG_KEY_CURRENTHASH "currenthash"
#define PMD_CONFIG_KEY_SERVERURL "serverurl"
#define PMD_CONFIG_KEY_COMPOSESERVER "composeserver"
#define PMD_CONFIG_KEY_API_SECURITY "apisecurity"

#define PMD_CONFIG_KEY_PRIVSEP_PUBKEY "pubkey"
#define PMD_CONFIG_KEY_PRIVSEP_PRIVKEY "privkey"

#define REST_COMMA "%2C"

#define PMD_DEFAULT_HASH  "DEADBEEFDEADBEEF"
