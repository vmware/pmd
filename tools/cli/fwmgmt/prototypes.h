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

//fwmgmt_main.c
uint32_t
fwmgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
fwmgmt_cli_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
fwmgmt_cli_get_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
fwmgmt_cli_add_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
fwmgmt_cli_delete_rules_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
fwmgmt_cli_restore_cmd(
    PPMDHANDLE hPMD,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

void
fwmgmt_cli_show_help(
    );

//fwmgmt_parseargs.c
uint32_t
fwmgmt_parse_args(
    int argc,
    char* const* argv,
    PFWMGMT_CMD_ARGS* ppCmdArgs
    );

uint32_t
fwmgmt_options_error(
    const char *pszName,
    const char *pszArg
    );

uint32_t
fwmgmt_parse_option(
    const char* pszName,
    const char* pszArg,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
fwmgmt_validate_options(
    const char *pszName,
    const char *pszArg,
    PFWMGMT_CMD_ARGS pCmdArgs
    );

void
fwmgmt_free_cmd_args(
    PFWMGMT_CMD_ARGS pCmdArgs
    );
