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
//jsonutils.c
uint32_t
get_json_object_from_string(
    const char *pszString,
    json_t **ppJsonObject
    );

uint32_t
get_json_string(
    PKEYVALUE pKeyValue,
    char **ppszJson
    );

uint32_t
make_keyvalue(
    const char* pszKey,
    const char* pszValue,
    PKEYVALUE *ppKeyValue
    );

void
free_keyvalue(
    PKEYVALUE pKeyValue
    );

uint32_t
json_get_opt_string_value(
    json_t *pRoot,
    const char *pszKey,
    char **ppszValue
    );

uint32_t
json_get_string_value(
    json_t *pRoot,
    const char *pszKey,
    char **ppszValue
    );

uint32_t
json_get_string_array(
    json_t *pJson,
    const char *pszKey,
    int *pnCount,
    char ***pppszValues
    );

uint32_t
json_make_result_success(
    char **ppszOutput
    );

uint32_t
json_string_from_key_value(
    const char *pszKey,
    const char *pszValue,
    char **ppszJsonString
    );
