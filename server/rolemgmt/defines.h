/*
 * Copyright 2016-2017 VMware, Inc. All rights reserved.
 * This software is released under the BSD 2-Clause license.
 * The full license information can be found in the LICENSE
 * in the root directory of this project.
 * SPDX-License-Identifier: BSD-2
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
