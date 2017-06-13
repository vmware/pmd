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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _PMD_CMD_ARGS
{
    char *pszServer;
    char *pszUser;
    char *pszDomain;
    char *pszPass;
    char *pszSpn;
    int nCmdCount;
    char **ppszCmds;
}PMD_CMD_ARGS, *PPMD_CMD_ARGS;


typedef uint32_t (*PFN_PMD_CMD)(PPMDHANDLE, PPMD_CMD_ARGS);

//Map command name to client function
typedef struct _PMD_CLI_CMD_MAP
{
    char* pszCmdName;
    PFN_PMD_CMD pFnCmd;
}PMD_CLI_CMD_MAP, *PPMD_CLI_CMD_MAP;

//component entry point
typedef uint32_t (*PFN_COMP_MAIN)(int, char* const*, PPMD_CMD_ARGS);

//Component info
typedef struct _PMD_KNOWN_COMPONENT
{
    const char* pszName;
    const char* pszDescription;
    PFN_COMP_MAIN pfnMain;
}PMD_KNOWN_COMPONENT, *PPMD_KNOWN_COMPONENT;

#ifdef __cplusplus
}
#endif
