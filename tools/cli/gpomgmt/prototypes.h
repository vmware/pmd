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

//gpomgmt_main.c
uint32_t
gpomgmt_main(
    int argc,
    char* const* argv,
    PPMD_CMD_ARGS pMainArgs
    );


uint32_t
gpomgmt_cli_show_version_cmd(
    PPMDHANDLE hPMD,
    PGPOMGMT_CMD_ARGS pCmdArgs
    );    

//gpomgmt_parseargs.c
uint32_t
gpomgmt_parse_args(
    int argc,
    char* const* argv,
    PGPOMGMT_CMD_ARGS* ppCmdArgs
    );
void
gpomgmt_free_cmd_args(
    PGPOMGMT_CMD_ARGS pCmdArgs
    );

//gpomgmt_help.c
void
gpomgmt_cli_show_help(
    );



