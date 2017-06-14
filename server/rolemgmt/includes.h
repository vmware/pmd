/*
 * Copyright 2016-2017 VMware, Inc. All rights reserved.
 * This software is released under the BSD 2-Clause license.
 * The full license information can be found in the LICENSE
 * in the root directory of this project.
 * SPDX-License-Identifier: BSD-2
*/

#pragma once
#include <lw/base.h>
#include <lw/types.h>

#include <stdio.h>
#include <string.h>
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
#include "defines.h"
#include "structs.h"

#include "rolemgmt_global.h"

#include "prototypes.h"
#include "../../jsonutils/prototypes.h"
