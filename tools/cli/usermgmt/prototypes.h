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

//usermgmt_main.c
uint32_t
usermgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_get_userid_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_get_groupid_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_get_users_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_get_groups_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_useradd_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_userdel_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_groupadd_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

uint32_t
usermgmt_cli_groupdel_cmd(
    PPMDHANDLE hPMD,
    PUSERMGMT_CMD_ARGS pCmdArgs
    );

void
usermgmt_cli_show_help(
    );

//usermgmt_parseargs.c
uint32_t
usermgmt_parse_args(
    int argc,
    char* const* argv,
    PUSERMGMT_CMD_ARGS* ppCmdArgs
    );

void
usermgmt_free_cmd_args(
    PUSERMGMT_CMD_ARGS pCmdArgs
    );
