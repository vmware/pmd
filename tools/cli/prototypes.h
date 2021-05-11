/*
 * Copyright © 2016-2021 VMware, Inc.  All Rights Reserved.
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

//component main functions
uint32_t
demo_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs);

uint32_t
fwmgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs);

uint32_t
pkg_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs);

uint32_t
netmgr_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs);

uint32_t
rolemgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs);

uint32_t
usermgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs);

//main.c
uint32_t
get_error_string(
    uint32_t dwErrorCode,
    char** ppszError
    );
uint32_t
print_error(
    uint32_t dwErrorCode
    );

uint32_t
net_version(
    PPMDHANDLE hPMD,
    PPMD_CMD_ARGS pCmdArgs
    );

void
show_version(
    );

uint32_t
route_cmd(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pCmdArgs
    );

void
ShowRegisteredComponents(
    PPMD_KNOWN_COMPONENT pKnownComps
    );

//help.c
void
show_usage(
    );

void
show_help(
    );

void
show_options_usage(
    );

void
show_no_such_cmd(
    const char* pszCmd
    );

void
show_no_such_option(
    const char* pszOption
    );

uint32_t
help_cmd(
    PPMDHANDLE hPMD,
    PPMD_CMD_ARGS pCmdArgs
    );

//parseargs.c
uint32_t
parse_comp_cmd(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS* ppCmdArgs
    );

uint32_t
parse_option(
    const char* pszName,
    const char* pszArg,
    PPMD_CMD_ARGS pCmdArgs
    );

uint32_t
collect_extra_args(
    int argIndex,
    int argc,
    char* const* argv,
    char*** pppszCmds,
    int* pnCmdCount
    );

void
free_cmd_args(
    PPMD_CMD_ARGS pCmdArgs
    );

//utils.c

int
PMDIsSystemError(
    uint32_t dwError
    );

uint32_t
PMDGetSystemErrorString(
    uint32_t dwSystemError,
    char** ppszError
    );
