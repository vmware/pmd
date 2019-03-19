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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <dirent.h>
#include <dlfcn.h>
#include <uuid/uuid.h>

#include <jansson.h>
#include <copenapi/copenapi.h>

#include <pmd_rolemgmt.h>
#include <roleplugin.h>

#include "../../idl/rolemgmt_h.h"

#include "../../common/defines.h"
#include "../../common/structs.h"
#include "../../common/prototypes.h"
#include "../../include/pmderror.h"
#include "../server/defines.h"
#include "defines.h"
#include "structs.h"

#include "rolemgmt_global.h"

#include "prototypes.h"
#include "../../jsonutils/prototypes.h"
