/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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
//pkgmgmt_utils.c
uint32_t
pkg_get_cmd_string(
    TDNF_ALTERTYPE nAlterType,
    char ** ppszAlterCmd
    );

uint32_t
pkg_translate_alter_cmd(
    int nPkgCount,
    TDNF_ALTERTYPE alterType,
    TDNF_ALTERTYPE *palterTypeToUse
    );


//utils.c
const char *
py_link_state_to_string(
    NET_LINK_STATE state
    );

const char *
py_link_mode_to_string(
    NET_LINK_MODE mode
    );

uint32_t
py_list_as_string_list(
    PyObject *pyList,
    char ***pppszStrings,
    size_t *pnCount
    );

uint32_t
py_string_as_string(
    PyObject *pyObj,
    PyObject **ppString
    );

char *
string_from_py_string(
    PyObject *pyString
    );

void
raise_exception(
    uint32_t dwErrorCode
    );

//pkgmgmt_repodata.c
uint32_t
py_make_repodata(
   PTDNF_REPO_DATA pRepoData,
   PyObject **ppPyRepoData
   );

//pkgmgmt_package.c
uint32_t
py_make_package(
   PTDNF_PKG_INFO pPackage,
   PyObject **ppPyPackage
   );

//pkgmgmt_solvedinfo.c
uint32_t
py_make_solvedinfo(
   PTDNF_SOLVED_PKG_INFO pSolvedInfo,
   PyObject **ppPySolvedInfo
   );

//rolemgmt_role_py.c
uint32_t
rolemgmt_role_py_make(
    PPMD_ROLEMGMT_ROLE pRole,
    PyObject **ppPyRole
    );

//rolemgmt_prereq_py.c
uint32_t
rolemgmt_prereq_py_make(
    PPMD_ROLE_PREREQ pPrereq,
    PPY_ROLEMGMT_PREREQ *ppPyPrereq
    );

//rolemgmt_logentry_py.c
uint32_t
rolemgmt_logentry_py_make(
    PPMD_ROLEMGMT_TASK_LOG pLogEntry,
    PPY_ROLEMGMT_LOG_ENTRY *ppPyLogEntry
    );
