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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>

#include <dce/rpc.h>

#include <vmrest.h>
#include <jansson.h>
#include <copenapi/copenapi.h>

#ifdef DEMO_ENABLED
#include "../../idl/demo_h.h"
#endif

#include "../../common/defines.h"
#include "../../common/structs.h"
#include "../../common/prototypes.h"
#include "../../include/pmderror.h"
#include "../../server/defines.h"
#include "../server/restutils/defines.h"
#include "../server/restutils/structs.h"
#include "../../jsonutils/structs.h"
#include "../../jsonutils/prototypes.h"

#include "defines.h"
#include "prototypes.h"
