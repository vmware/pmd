*
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

#define PMD_ROLEMGMT_VERSION "0.1"

#define PMD_ROLE_EXT     ".role"
#define PMD_ROLE_EXT_LEN 5
#define PMD_ROLES_DIR    "/etc/pmd.roles.d"
#define PMD_ROLE_PLUGINS_DIR    "/etc/pmd.roles.plugins.d"

#define ROLE_CONF_NAME         "name"
#define ROLE_CONF_DISPLAY_NAME "displayname"
#define ROLE_CONF_DESCRIPTION  "description"
#define ROLE_CONF_PARENT       "parent"
#define ROLE_CONF_PLUGIN       "plugin"

#define UUID_STR_LEN           37

//Function name defs
#define PMD_ROLEPLUGIN_LOAD_INTERFACE   "pmd_roleplugin_load_interface"
#define PMD_ROLEPLUGIN_UNLOAD_INTERFACE "pmd_roleplugin_unload_interface"

//load
typedef uint32_t
(*PFN_PMD_ROLEPLUGIN_LOAD_INTERFACE)(
    PPMD_ROLE_PLUGIN_INTERFACE *ppRoleInterface
    );

//unload
typedef uint32_t
(*PFN_PMD_ROLEPLUGIN_UNLOAD_INTERFACE)(
    PPMD_ROLE_PLUGIN_INTERFACE pRoleInterface
    );
