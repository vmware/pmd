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

#ifdef __cplusplus
extern "C" {
#endif

//PMD specific errors(3000 to 3999)
#define ERROR_PMD_BASE                  3000
#define ERROR_PMD_FAIL                  (ERROR_PMD_BASE + 1)
#define ERROR_PMD_NOTHING_TO_DO         (ERROR_PMD_BASE + 2)
#define ERROR_PMD_CONF_FILE_LOAD        (ERROR_PMD_BASE + 3)
#define ERROR_PMD_BASE64_ENCODE         (ERROR_PMD_BASE + 4)
#define ERROR_PMD_BASE64_DECODE         (ERROR_PMD_BASE + 5)
#define ERROR_PMD_USER_PASS_FORMAT      (ERROR_PMD_BASE + 6)
#define ERROR_PMD_JSON_SET_VALUE        (ERROR_PMD_BASE + 7)
#define ERROR_PMD_ROLES_DIR_OPEN        (ERROR_PMD_BASE + 21)
#define ERROR_PMD_ROLES_NO_SUCH_ROLE    (ERROR_PMD_BASE + 22)
#define ERROR_PMD_ROLES_PLUGIN_NOT_SET  (ERROR_PMD_BASE + 23)
#define ERROR_PMD_ROLE_CONFIG_NO_PARENT (ERROR_PMD_BASE + 24)
#define ERROR_PMD_ROLE_UNMAPPED_FN      (ERROR_PMD_BASE + 25)
#define ERROR_PMD_ROLE_UNMAPPED_LOAD    (ERROR_PMD_BASE + 26)
#define ERROR_PMD_ROLE_PLUGIN_BAD       (ERROR_PMD_BASE + 27)
#define ERROR_PMD_ROLE_PLUGIN_DISABLED  (ERROR_PMD_BASE + 28)
#define ERROR_PMD_ROLE_PLUGIN_HAS_TASKS (ERROR_PMD_BASE + 29)
#define ERROR_PMD_ROLE_TASK_NOT_FOUND   (ERROR_PMD_BASE + 30)
#define ERROR_PMD_ROLE_TASK_NO_LOGS     (ERROR_PMD_BASE + 31)
#define ERROR_PMD_ROLE_PATH_MISMATCH    (ERROR_PMD_BASE + 32)

//REST specific errors (3500 to 3600)
#define ERROR_PMD_REST_BASE                3500
#define ERROR_PMD_REST_AUTH_REQUIRED       (ERROR_PMD_REST_BASE + 1)
#define ERROR_PMD_REST_AUTH_BASIC_MIN      (ERROR_PMD_REST_BASE + 2)

//System errors 3600 and up
#define ERROR_PMD_SYSTEM_BASE           3600
// No search results found
#define ERROR_PMD_NO_SEARCH_RESULTS     3601
#define ERROR_PMD_INVALID_PARAMETER     (ERROR_PMD_SYSTEM_BASE + EINVAL)
#define ERROR_PMD_OUT_OF_MEMORY         (ERROR_PMD_SYSTEM_BASE + ENOMEM)
#define ERROR_PMD_NO_DATA               (ERROR_PMD_SYSTEM_BASE + ENODATA)
#define ERROR_PMD_FILE_NOT_FOUND        (ERROR_PMD_SYSTEM_BASE + ENOENT)
#define ERROR_PMD_ACCESS_DENIED         (ERROR_PMD_SYSTEM_BASE + EACCES)
#define ERROR_PMD_ALREADY_EXISTS        (ERROR_PMD_SYSTEM_BASE + EEXIST)
#define ERROR_PMD_LIBACC                (ERROR_PMD_SYSTEM_BASE + ELIBACC)
#define ERROR_PMD_ALREADY               (ERROR_PMD_SYSTEM_BASE + EALREADY)
#define ERROR_PMD_SYSTEM_END            ERROR_PMD_SYSTEM_BASE + 127

//pkgmgmt errors 4000 and up
#define ERROR_PMD_PKG_BASE              4000
#define ERROR_PMD_MISSING_PKG_ARGS      (ERROR_PMD_PKG_BASE + 1)
#define ERROR_PMD_ALTER_MODE_INVALID    (ERROR_PMD_PKG_BASE + 2)

//usermgmt errors 4100 and up
#define ERROR_PMD_USER_BASE             4100

#ifdef __cplusplus
}
#endif
