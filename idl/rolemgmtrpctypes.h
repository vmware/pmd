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

#ifndef __ROLEMGMT_RPC_TYPES_H__
#define __ROLEMGMT_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#if (!defined NO_LIKEWISE && !defined _WIN32)
#include <lw/types.h>
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <rolemgmtrpctypes.h>")
cpp_quote("#if 0")

#endif

typedef enum
{
    RPC_ROLE_STATE_IDLE,
    RPC_ROLE_STATE_ALTER,
    RPC_ROLE_STATE_PREREQ
}RPC_ROLE_STATE;

typedef enum
{
    RPC_ROLE_OPERATION_NONE,
    RPC_ROLE_OPERATION_ENABLE,
    RPC_ROLE_OPERATION_UPDATE,
    RPC_ROLE_OPERATION_REMOVE
}RPC_ROLE_OPERATION;

typedef enum
{
    RPC_ROLE_STATUS_NONE,
    RPC_ROLE_STATUS_SUCCESS,
    RPC_ROLE_STATUS_FAILURE,
    RPC_ROLE_STATUS_NOT_STARTED,
    RPC_ROLE_STATUS_IN_PROGRESS
}RPC_ROLE_STATUS;

typedef struct _PMD_RPC_ROLEMGMT_ROLE_
{
    wstring_t pwszId;
    wstring_t pwszName;
    wstring_t pwszDisplayName;
    wstring_t pwszDescription;
}PMD_RPC_ROLEMGMT_ROLE, *PPMD_RPC_ROLEMGMT_ROLE;

typedef struct _PMD_RPC_ROLEMGMT_ROLE_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_ROLEMGMT_ROLE pRoles;
}PMD_RPC_ROLEMGMT_ROLE_ARRAY, *PPMD_RPC_ROLEMGMT_ROLE_ARRAY;

typedef struct _PMD_RPC_ROLEMGMT_PREREQ_
{
    wstring_t pwszName;
    wstring_t pwszDescription;
}PMD_RPC_ROLEMGMT_PREREQ, *PPMD_RPC_ROLEMGMT_PREREQ;

typedef struct _PMD_RPC_ROLEMGMT_STATUS_
{
    RPC_ROLE_STATE nState;
    unsigned32 nSecondsElapsed;
    unsigned32 nPercentCompleted;
    wstring_t pwszStatus;
}PMD_RPC_ROLEMGMT_STATUS, *PPMD_RPC_ROLEMGMT_STATUS;

typedef struct _PMD_RPC_ROLEMGMT_PREREQ_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_ROLEMGMT_PREREQ pPrereqs;
}PMD_RPC_ROLEMGMT_PREREQ_ARRAY, *PPMD_RPC_ROLEMGMT_PREREQ_ARRAY;

typedef struct _PMD_RPC_ROLEMGMT_TASK_LOG_
{
    unsigned long int tStamp;
    wstring_t pwszLog;
}PMD_RPC_ROLEMGMT_TASK_LOG, *PPMD_RPC_ROLEMGMT_TASK_LOG;

typedef struct _PMD_RPC_ROLEMGMT_TASK_LOG_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PPMD_RPC_ROLEMGMT_TASK_LOG pTaskLogs;
}PMD_RPC_ROLEMGMT_TASK_LOG_ARRAY, *PPMD_RPC_ROLEMGMT_TASK_LOG_ARRAY;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __ROLEMGMT_RPC_TYPES_H__ */
