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

typedef struct _DEMO_CMD_ARGS_
{
    int nShowHelp;
    int nShowVersion;
    int nCmdCount;
    char **ppszCmds;
}DEMO_CMD_ARGS, *PDEMO_CMD_ARGS; 

typedef uint32_t (*PFN_DEMO_CMD)(PPMDHANDLE, PDEMO_CMD_ARGS);

typedef struct _DEMO_CLI_CMD_MAP
{
    char* pszCmdName;
    PFN_DEMO_CMD pFnCmd;
}DEMO_CLI_CMD_MAP, *PDEMO_CLI_CMD_MAP;
