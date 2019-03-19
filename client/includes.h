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

#include <lw/base.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dce/rpc.h>
#include <dce/dcethread.h>
#include <dce/dce_error.h>

#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#include "../idl/fwmgmt_h.h"
#include "../idl/pkgmgmt_h.h"
#include "../idl/pmd_h.h"
#include "../idl/netmgmt_h.h"
#include "../idl/rolemgmt_h.h"
#include "../idl/rpmostree_h.h"
#include "../idl/usermgmt_h.h"

#include "../idl/privsepd_h.h"
#include "../idl/pkgmgmt_privsep_h.h"
#include "../idl/netmgmt_privsep_h.h"
#include "../idl/fwmgmt_privsep_h.h"
#include "../idl/usermgmt_privsep_h.h"

#ifdef DEMO_ENABLED
#include "../idl/demo_h.h"
#include "../idl/demo_privsep_h.h"
#endif

#include "../common/includes.h"

#include <tdnf/tdnftypes.h>
#include <pmd.h>
#include <pmd_fwmgmt.h>
#include <pmd_pkgmgmt.h>
#include <pmd_rolemgmt.h>
#include <pmd_usermgmt.h>

#include "defines.h"
#include "structs.h"
#include "prototypes.h"

#include <netmgmt/netmgr.h>
#include "pmd_netmgr.h"
#include <gssapi_creds_plugin.h>
