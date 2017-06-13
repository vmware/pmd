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

typedef enum _FWMGMT_OPERATION
{
    FWMGMT_OPERATION_LIST   = 0x1,
    FWMGMT_OPERATION_SET    = 0x2,
    FWMGMT_OPERATION_DELETE = 0x4
}FWMGMT_OPERATION;

typedef struct _FWMGMT_CMD_ARGS_
{
    int nShowHelp;
    int nShowVersion;
    int nCmdCount;
    int nIPV6;
    int nPersist;
    FWMGMT_OPERATION nOperation;
    char *pszOpArgs;
    char *pszChain;
    char **ppszCmds;
}FWMGMT_CMD_ARGS, *PFWMGMT_CMD_ARGS; 

typedef uint32_t (*PFN_FWMGMT_CMD)(PPMDHANDLE, PFWMGMT_CMD_ARGS);

typedef struct _FWMGMT_CLI_CMD_MAP
{
    char* pszCmdName;
    PFN_FWMGMT_CMD pFnCmd;
}FWMGMT_CLI_CMD_MAP, *PFWMGMT_CLI_CMD_MAP;
