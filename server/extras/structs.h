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

typedef struct _PARAM_SPEC_
{
    char *pszName;
    char chFlag;
    int nArgRequired;
}PARAM_SPEC, *PPARAM_SPEC;

typedef struct _PARAM_
{
    int nFlag;
    char *pszName;
    char *pszValue;
    struct _PARAM_ *pNext;
}PARAM, *PPARAM;

typedef enum _PARSE_STATE_
{
    PARSE_STATE_BEGIN,
    PARSE_STATE_READY,
    PARSE_STATE_FLAG,
    PARSE_STATE_FLAGVALUE
}PARSE_STATE;

typedef struct _PARSE_CONTEXT_
{
    PARSE_STATE parseState;
    char *pszCmd;
    PPMD_FIREWALL_PARAM pParams;
}PARSE_CONTEXT, *PPARSE_CONTEXT;

typedef enum _IPTABLES_SCRIPT_LINE_TYPE_
{
    SCRIPT_LINE_EMPTY,
    SCRIPT_LINE_COMMENT,
    SCRIPT_LINE_UNKNOWN,
    SCRIPT_LINE_RULE
}IPTABLES_SCRIPT_LINE_TYPE;

typedef enum _IPTABLES_RULE_ACTION_
{
    RULE_ACTION_KEEP,
    RULE_ACTION_ALTER,
    RULE_ACTION_DELETE
}IPTABLES_RULE_ACTION;

typedef struct _IPTABLES_RULE_
{
    IPTABLES_RULE_ACTION nAction;   
    char *pszOriginal;
    char *pszNew;
}IPTABLES_RULE, *PIPTABLES_RULE;

typedef struct _IPTABLES_SCRIPT_LINE_
{
    IPTABLES_SCRIPT_LINE_TYPE nType;
    union
    {
        char *pszComment;
        char *pszUnknown;
        PIPTABLES_RULE pRule;
    };
    struct _IPTABLES_SCRIPT_LINE_ *pNext;
    struct _IPTABLES_SCRIPT_LINE_ *pPrev;
}IPTABLES_SCRIPT_LINE, *PIPTABLES_SCRIPT_LINE;

typedef struct _IPTABLES_SCRIPT_DATA_
{
    char *pszFileName;
    PIPTABLES_SCRIPT_LINE pLines;
}IPTABLES_SCRIPT_DATA, *PIPTABLES_SCRIPT_DATA;
