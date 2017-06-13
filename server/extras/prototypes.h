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

//fwmgmt_api.c
uint32_t
pmd_firewall_get_rules(
    uint32_t nIPV6,
    PPMD_FIREWALL_RULE *ppFirewallRules
    );

uint32_t
pmd_firewall_add_rules(
    uint32_t nIPV6,
    uint32_t nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    );

uint32_t
pmd_firewall_delete_rules(
    uint32_t nIPV6,
    uint32_t nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    );

uint32_t
pmd_firewall_restore(
    int nIPV6,
    PPMD_FIREWALL_TABLE pTable
    );

//fwmgmt_restapi.c
uint32_t
firewall_rest_get_version(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_get_rules(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_get_rules6(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_put_rules(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
firewall_rest_delete_rules(
    void *pInputJson,
    void **ppOutputJson
    );

//iptables_rule_parser.c
uint32_t
param_is_flag(
    const char *pszArg,
    int *pnFlag
    );

void
free_param(
    PPMD_FIREWALL_PARAM pParam
    );

void
free_params(
    PPMD_FIREWALL_PARAM pParams
    );

uint32_t
params_parse_string(
    const char *pszString,
    PPARSE_CONTEXT pContext
    );

//iptables_script_reader.c
uint32_t
read_iptables_script_file(
    const char *pszFile,
    PIPTABLES_SCRIPT_DATA *ppData
    );

uint32_t
process_script_line(
    const char *pszInputLine,
    PIPTABLES_SCRIPT_LINE *ppLine
    );

uint32_t
write_iptables_script_file(
    const char *pszFile,
    PIPTABLES_SCRIPT_DATA pData
    );

void
free_iptables_script_line(
    PIPTABLES_SCRIPT_LINE pLine
    );

void
free_iptables_script_data(
    PIPTABLES_SCRIPT_DATA pData
    );

void
free_parse_context(
    PPARSE_CONTEXT pContext
    );

//fwmgmt_utils.c
uint32_t
get_firewall_rules(
    PIPTABLES_SCRIPT_DATA pData,
    PPMD_FIREWALL_RULE *ppFirewallRules
    );

uint32_t
add_firewall_rule_to_script(
    const char *pszRule
    );

uint32_t
delete_firewall_rule_from_script(
    const char *pszRule
    );

uint32_t
get_restore_cmd(
    const char *pszCmd,
    char **ppszRestoreCmd
    );

//rolemgmt_api.c
uint32_t
pmd_rolemgmt_get_version(
    char **ppszVersion
    );

uint32_t
pmd_rolemgmt_get_roles(
    PPMD_ROLEMGMT_ROLE *ppRoles
    );

//usrmgmt_api.c
uint32_t
pmd_usermgmt_get_version(
    char **ppszVersion
    );

uint32_t
pmd_usermgmt_add_user(
    char *pszName
    );

uint32_t
pmd_usermgmt_delete_user(
    char *pszName
    );

uint32_t
pmd_usermgmt_add_group(
    char *pszName
    );

uint32_t
pmd_usermgmt_delete_group(
    char *pszName
    );

uint32_t
pmd_usermgmt_get_userid(
    const char *pszName,
    uint32_t *pnUID
    );

uint32_t
pmd_usermgmt_get_groupid(
    const char *pszName,
    uint32_t *pnGID
    );

uint32_t
pmd_usermgmt_get_users(
    PPMD_USER *ppUsers
    );

uint32_t
pmd_usermgmt_get_groups(
    PPMD_GROUP *ppGroups
    );

uint32_t
pmd_usermgmt_get_users_for_group(
    uint32_t nGroupID,
    char ***pppszUsers,
    int *pnUserCount
    );

uint32_t
pmd_usermgmt_add_user_to_group(
    uint32_t nUserID,
    uint32_t nGroupID
    );

uint32_t
pmd_usermgmt_remove_user_from_group(
    uint32_t nUserID,
    uint32_t nGroupID
    );

void
usermgmt_free_user(
    PPMD_USER pUser
    );

void
usermgmt_free_group(
    PPMD_GROUP pGroup
    );

//usermgmt_restapi.c
uint32_t
usrmgmt_rest_get_users(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_get_userid(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_put_user(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_delete_user(
    void *pInputJson,
    void **ppOutputJson
    );
//groups
uint32_t
usrmgmt_rest_get_groups(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_get_groupid(
    void *pInputJson,
    void **ppszOutputJson
    );

uint32_t
usrmgmt_rest_put_group(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
usrmgmt_rest_delete_group(
    void *pInputJson,
    void **ppOutputJson
    );
//security
uint32_t has_admin_access(
    rpc_binding_handle_t h
    );
