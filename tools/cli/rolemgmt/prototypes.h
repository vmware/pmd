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

//rolemgmt_main.c
uint32_t
rolemgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_roles_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_get_roles_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_get_logs_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_get_version_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_get_prereqs_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_get_status_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_cli_alter_cmd(
    PPMDHANDLE hPMD,
    PROLEMGMT_CMD_ARGS pCmdArgs,
    PMD_ROLE_OPERATION nOperation
    );

void
rolemgmt_cli_show_help(
    );

//rolemgmt_parseargs.c
uint32_t
rolemgmt_parse_args(
    int argc,
    char* const* argv,
    PROLEMGMT_CMD_ARGS* ppCmdArgs
    );

uint32_t
rolemgmt_options_error(
    const char *pszName,
    const char *pszArg
    );

uint32_t
rolemgmt_validate_options(
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_parse_option(
    const char* pszName,
    const char* pszArg,
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

void
rolemgmt_free_cmd_args(
    PROLEMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
rolemgmt_status_to_string(
    PMD_ROLE_STATUS nStatus,
    char **ppszStatus
    );
