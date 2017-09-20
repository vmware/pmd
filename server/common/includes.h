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
#include <stdint.h>
#include <termios.h>

#include <dce/rpc.h>
#include <dce/dcethread.h>
#include <dce/dce_error.h>

#include <pmderror.h>
 
#include "../idl/pmdrpctypes.h"
#include "../idl/pkgmgmtrpctypes.h"

#include <tdnf/tdnftypes.h>
#include <pmd_pkgmgmt.h>

#include "../../common/includes.h"
#include "defines.h"
#include "pkgmgmt_utils.h"
#include "prototypes.h"
