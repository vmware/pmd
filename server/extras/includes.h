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
#include "../../common/includes.h"

#include <pwd.h>
#include <grp.h>

#include <jansson.h>
#include <copenapi/copenapi.h>

#include "../../idl/usermgmt_h.h"
#include "pmd_usermgmt_types.h"

#include "../../idl/fwmgmt_h.h"
#include "pmd_fwmgmt.h"

#include "prototypes.h"
#include "../../jsonutils/prototypes.h"

#include "../security/defines.h"
