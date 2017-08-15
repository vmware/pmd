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

//gpwrappers.c
uint32_t
pmd_gpmgmt_load_policies(
    PPMD_POLICY_DATA *ppPolicies
    );

uint32_t
pmd_gpmgmt_print_polices(
    PPMD_POLICY_DATA pPolicies
    );

uint32_t
pmd_gpmgmt_load_each_policy(
    const char *pszPolicyName,
    json_t *pPolicyData,
    PPMD_POLICY_DATA *ppPolicy
    );

uint32_t
pmd_gpmgmt_create_policy_json(
        );

void
gpmgmt_free_policies(
    PPMD_POLICY_DATA pPolicies
    );

//gpsqllogs.c
uint32_t
gpmgmt_sql_create_logs(
    const char *pszAppDBPath,
    sqlite3 **ppDB
    );

uint32_t
gpmgmt_sql_check_if_table_exists(
    sqlite3 *pDB,
    const char *psztableName,
    uint32_t *bExist
    );

uint32_t
gpmgmt_sql_bind_string(
    sqlite3_stmt *pSqlStatement,
    const char *pszParamName,
    const char *pszValue
    );

uint32_t
gpmgmt_sql_step_sql(
    sqlite3_stmt *hs
    );

uint32_t
gpmgmt_sql_get_column_int(
    sqlite3_stmt *pSqlStatement,
    const char *pszColumnName,
    uint32_t *pdwValue
    );


uint32_t
gpmgmt_sql_get_column_index_from_name(
    sqlite3_stmt *pSqlStatement,
    const char *pszCloumnName
    );

uint32_t
gpmgmt_sql_execute_transaction(
    sqlite3 *pDB,
    const char *sqlStr
    );

uint32_t
gpmgmt_sql_begin_transaction(
    sqlite3 *pDB
    );

uint32_t
gpmgmt_sql_commit_transaction(
    sqlite3 *pDB
    );

void
gpmgmt_sql_database_close(
    sqlite3 *pDB
    );

uint32_t
gpmgmt_sql_rollback_transaction(
    sqlite3 *pDB
    );

uint32_t
gpmgmt_sql_add_log(
    sqlite3 *pDB,
    const PPMD_POLICY_LOG pLogEntry
    );

uint32_t
gpmgmt_sql_query_all_logs(
    sqlite3 *pDb,
    PPMD_POLICY_LOG *ppLogEntryArray,
    uint32_t *pdwCount
    );

uint32_t
gpmgmt_sql_get_log_count(
                    sqlite3 *pDB,
                    const char * pszIsSuccessful,
                    uint32_t *pdwCount
                    );

uint32_t
gpmgmt_sql_copy_row(
    sqlite3_stmt *pSqlStatement,
    PPMD_POLICY_LOG *ppEntry
    );

uint32_t
gpmgmt_sql_get_column_string(
    sqlite3_stmt* pSqlStatement,
    const char * pszColumnName,
    char ** ppszValue
    );

void
gpmgmt_sql_free_log_entry(
    PPMD_POLICY_LOG pLogEntry
    );

uint32_t
gpmgmt_sql_bind_dword(
    sqlite3_stmt* pSqlStatement,
    const char * pszParamName,
    uint32_t dwValue
    );

uint32_t
gpmgmt_sql_print_logs(
    PPMD_POLICY_LOG pLogEntry
    );