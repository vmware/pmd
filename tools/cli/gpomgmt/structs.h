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

//TODO: imported the stsructure from FWMGMT, remove unnecessary arguments later
typedef struct _GPOMGMT_CMD_ARGS_
{
    int nShowHelp;
    int nShowVersion;
    /*int nCmdCount;
    int nIPV6;
    int nPersist;
    GPOMGMT_OPERATION nOperation;
    char *pszOpArgs;
    char *pszChain;
    char **ppszCmds; */
}GPOMGMT_CMD_ARGS, *PGPOMGMT_CMD_ARGS; 

typedef uint32_t (*PFN_GPOMGMT_CMD)(PPMDHANDLE, PGPOMGMT_CMD_ARGS);

typedef struct _GPOMGMT_CLI_CMD_MAP
{
    char* pszCmdName;
    PFN_GPOMGMT_CMD pFnCmd;
}GPOMGMT_CLI_CMD_MAP, *PGPOMGMT_CLI_CMD_MAP;
