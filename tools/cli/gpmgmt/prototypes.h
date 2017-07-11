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

//gpmgmt_main.c
uint32_t
gpmgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs
    );


uint32_t
gpmgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PgpMGMT_CMD_ARGS pCmdArgs
    );    

//gpmgmt_parseargs.c
uint32_t
gpmgmt_parse_args(
    int argc,
    char* const* argv,
    PgpMGMT_CMD_ARGS* ppCmdArgs
    );
void
gpmgmt_free_cmd_args(
    PgpMGMT_CMD_ARGS pCmdArgs
    );

//gpmgmt_help.c
void
gpmgmt_cli_show_help(
    );



