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

//pkg_main.c
uint32_t
pkg_exec_cmd(
    int argc,
    char* const* argv,
    PTDNF_CMD_ARGS pCmdArgs);

uint32_t
pkg_invoke_search(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_PKG_INFO* ppPkgInfo,
    uint32_t* punCount
    );

uint32_t
pkg_invoke_clean(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_CLEANTYPE nCleanType,
    PTDNF_CLEAN_INFO* ppCleanInfo
    );

uint32_t
pkg_invoke_check_update(
    PTDNF_CLI_CONTEXT pContext,
    char** ppszPackageArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

uint32_t
pkg_invoke_provides(
    PTDNF_CLI_CONTEXT pContext,
    const char *pszSpec,
    PTDNF_PKG_INFO* ppPkgInfo
    );

uint32_t
pkg_invoke_checklocal(
    PTDNF_CLI_CONTEXT pContext,
    const char *pszFolder
    );

uint32_t
pkg_invoke_alter(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO pSolvedPkgInfo
    );

uint32_t
pkg_invoke_count(
    PTDNF_CLI_CONTEXT pContext,
    uint32_t *pdwCount
    );

uint32_t
pkg_invoke_info(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_LIST_ARGS pInfoArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

uint32_t
pkg_invoke_list(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_LIST_ARGS pListArgs,
    PTDNF_PKG_INFO *ppPkgInfo,
    uint32_t *pdwCount
    );

uint32_t
pkg_invoke_repolist(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_REPOLISTFILTER nFilter,
    PTDNF_REPO_DATA *ppRepos
    );

uint32_t
pkg_invoke_reposync(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_REPOSYNC_ARGS pRepoSyncArgs
    );

uint32_t
pkg_invoke_resolve(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_ALTERTYPE nAlterType,
    PTDNF_SOLVED_PKG_INFO *ppSolvedPkgInfo
    );

uint32_t
pkg_invoke_updateinfo(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_UPDATEINFO_ARGS pInfoArgs,
    PTDNF_UPDATEINFO *ppUpdateInfo
    );

uint32_t
pkg_invoke_updateinfo_summary(
    PTDNF_CLI_CONTEXT pContext,
    TDNF_AVAIL nAvail,
    PTDNF_UPDATEINFO_ARGS pInfoArgs,
    PTDNF_UPDATEINFO_SUMMARY *ppSummary
    );

uint32_t
pkg_count_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_info_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_list_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_repolist_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_updateinfo_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_downgrade_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_distro_sync_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_erase_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_install_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_reinstall_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_update_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_alter_cmd(
    PPMDHANDLE hPMD,
    PTDNF_CMD_ARGS pCmdArgs,
    TDNF_ALTERTYPE nType
    );

uint32_t
pkg_serverinfo_cmd(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_ostree_sync_cmd(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_show_version_cmd(
    PTDNF_CLI_CONTEXT pContext,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_print_error(
    PPMDHANDLE hPMD,
    uint32_t dwErrorCode
    );

//pkg_parseargs.c
uint32_t
pkg_parse_args(
    int argc,
    char* const* argv,
    PTDNF_CMD_ARGS* ppCmdArgs
    );

uint32_t
pkg_parse_option(
    const char* pszName,
    const char* pszArg,
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
pkg_copy_options(
    PTDNF_CMD_ARGS pOptionArgs,
    PTDNF_CMD_ARGS pArgs
    );

uint32_t
pkg_handle_options_error(
    const char* pszName,
    const char* pszArg,
    struct option* pstOptions
    );

uint32_t
pkg_parse_info_args(
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_LIST_ARGS* ppListArgs
    );

void
pkg_free_cmd_args(
    PTDNF_CMD_ARGS pCmdArgs
    );

uint32_t
parse_rpm_verbosity(
     const char *pszRpmVerbosity,
     int *pnRpmVerbosity
     );

//parselistargs.c
uint32_t
pkg_parse_scope(
    const char* pszScope,
    TDNF_SCOPE* pnScope
    );

uint32_t
pkg_parse_list_args(
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_LIST_ARGS* ppListArgs
    );

uint32_t
pkg_parse_info_args(
    PTDNF_CMD_ARGS pCmdArgs,
    PTDNF_LIST_ARGS* ppListArgs
    );

void
pkg_free_list_args(
    PTDNF_LIST_ARGS pListArgs
    );

//parserepolistargs.c
uint32_t
pkg_parse_filter(
    const char* pszRepolistFilter,
    TDNF_REPOLISTFILTER* pnFilter
    );

uint32_t
pkg_parse_repolist_args(
    PTDNF_CMD_ARGS pCmdArgs,
    TDNF_REPOLISTFILTER* pnFilter
    );
//help.c
void
pkg_show_help(
    );

// pkg_options.c
uint32_t
pkg_get_option_by_name(
    const char* pszName,
    struct option* pKnownOptions,
    struct option** ppOption
    );

uint32_t
pkg_validate_option_name(
    const char* pszOptionName,
    struct option* pKnownOptions
    );

uint32_t
pkg_validate_option_arg(
    const char* pszOption,
    const char* pszArg,
    struct option* pKnownOptions
    );

uint32_t
pkg_validate_options(
    const char* pszOption,
    const char* pszArg,
    struct option* pKnownOptions
    );

uint32_t
add_set_opt(
    PTDNF_CMD_ARGS pCmdArgs,
    const char* pszOptArg
    );

uint32_t
add_set_opt_with_values(
    PTDNF_CMD_ARGS pCmdArgs,
    int nType,
    const char *pszOptArg,
    const char *pszOptValue
    );

uint32_t
get_option_and_value(
    const char* pszOptArg,
    PTDNF_CMD_OPT* ppCmdOpt
    );

void
pmd_free_pkg_cmd_opt(
    PTDNF_CMD_OPT pCmdOpt
    );

