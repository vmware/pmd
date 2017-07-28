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
#include <lw/types.h>

#include <ctype.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <sys/sysinfo.h>
#include <sys/utsname.h>
#include <pwd.h>

#include <vmrest.h>
#include <netmgmt/netmgr.h>
#include <jansson.h>
#include <pmd.h>


//grouppolicy plugin
#include <dlfcn.h>
#include "pmd_gpmgmt.h"
#include "defines.h"
#include "prototypes.h"

#include "../../idl/gpmgmt_h.h"

#include "../../common/includes.h"

//jsonutils
#include "../../jsonutils/includes.h"

//restutils
#include "../../server/restutils/includes.h"

#include "../structs.h"
#include "../global.h"



