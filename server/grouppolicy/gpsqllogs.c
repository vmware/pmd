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

#include "includes.h"

uint32_t
gpmgmt_sql_create_logs(
    const char *pszAppDBPath,
    sqlite3 **ppDB
    )
{
    uint32_t dwError = 0;
    sqlite3 *pDB = NULL;
    bool bInTx = FALSE;
    uint32_t bTableExists = 0;

    if (!pszAppDBPath || !ppDB)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = sqlite3_open_v2(
        pszAppDBPath,
        &pDB,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
        NULL);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_check_if_table_exists(pDB, "LogsTable", &bTableExists);
    BAIL_ON_PMD_ERROR(dwError);

    if (bTableExists != 1)
    {

        dwError = gpmgmt_sql_execute_transaction(
            pDB,
            "PRAGMA page_size = 2048;");
        BAIL_ON_PMD_ERROR(dwError);

        dwError = gpmgmt_sql_execute_transaction(
            pDB,
            "PRAGMA default_cache_size = 10000;");
        BAIL_ON_PMD_ERROR(dwError);

        gpmgmt_sql_begin_transaction(pDB);
        bInTx = TRUE;

        dwError = gpmgmt_sql_execute_transaction(
            pDB,
            "CREATE TABLE IF NOT EXISTS LogsTable ("
            "LogID INTEGER PRIMARY KEY AUTOINCREMENT UNIQUE NOT NULL,"
            "IPAddress  VARCHAR(128),"
            "Time  VARCHAR(128),"
            "LogType VARCHAR(128) COLLATE NOCASE NOT NULL,"
            "PolicyName VARCHAR(256),"
            "IsSuccessful VARCHAR(128),"
            "ErrorStr VARCHAR(2048));");
        BAIL_ON_PMD_ERROR(dwError);

        gpmgmt_sql_commit_transaction(pDB);
    }

    *ppDB = pDB;

cleanup:
    return dwError;

error:
    if(pDB)
    {
        fprintf(stderr, "Creating the LogsTable table failed  %s\n", sqlite3_errmsg(pDB));
    }
    if (bInTx && pDB)
    {
        gpmgmt_sql_rollback_transaction(pDB);
    }
    if (ppDB)
    {
        *ppDB = NULL;
    }
    goto cleanup;
}

uint32_t
gpmgmt_sql_check_if_table_exists(
    sqlite3 *pDB,
    const char *psztableName,
    uint32_t *bExist
    )
{
    uint32_t dwError = 0;
    uint32_t dwEntriesAvailable = 0;
    char szQuery[] = "SELECT 1 as count FROM sqlite_master"
                     " WHERE type='table'"
                     " AND name=:table_name;";
    sqlite3_stmt *pSqlStatement = NULL;

    if(!pDB || !psztableName || !bExist)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = sqlite3_prepare_v2(
        pDB,
        szQuery,
        -1,
        &pSqlStatement,
        NULL);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_bind_string(pSqlStatement,
                                     ":table_name",
                                     psztableName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_step_sql(pSqlStatement);
    if ((dwError == SQLITE_ROW) || (dwError = SQLITE_DONE))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_int(
        pSqlStatement,
        "count",
        &dwEntriesAvailable);
    BAIL_ON_PMD_ERROR(dwError);

    if (dwEntriesAvailable == 1)
    {
        *bExist = 1;
    }

error:
    if (pSqlStatement != NULL)
    {
        sqlite3_finalize(pSqlStatement);
        pSqlStatement = NULL;
    }
    if(pDB && (dwError>0))
    {
        fprintf(stderr, "Checking the existance of table failed  %s\n , Error(%u)", 
                         sqlite3_errmsg(pDB),dwError);
    }
    return dwError;
}

uint32_t
gpmgmt_sql_bind_string(
    sqlite3_stmt *pSqlStatement,
    const char *pszParamName,
    const char *pszValue
    )
{
    uint32_t dwError = 0;
    int indx = -1;

    if (!pSqlStatement || !pszParamName)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    indx = sqlite3_bind_parameter_index(pSqlStatement, pszParamName);
    // This returns zero when pszParam Name is not found, which is
    // little strange since it means SQLITE_OK :(
    if (indx == 0)
    {
        dwError = SQLITE_NOTFOUND;
    }
    BAIL_ON_PMD_ERROR(dwError);

    // if the data string does not live thru the SQL Operation,
    // SQLITE_STATIC need to be converted to SQLITE_TRANSIENT
    // if it is TRANSIENT, SQLite will make a copy of the data
    // and keep it around for the sql_step function.
    //
    // However in the case of VECS the copy is not needed and we are
    // *not* making a copy of the data.
    // if the data is destroyed before the actual SQL operation happens
    // it can lead to failures.

    if (pszValue)
    {
        dwError = sqlite3_bind_text(
            pSqlStatement,
            indx,
            pszValue,
            -1,
            SQLITE_STATIC);
    }
    else
    {
        dwError = sqlite3_bind_null(pSqlStatement, indx);
    }
    BAIL_ON_PMD_ERROR(dwError);

error:
    if(dwError)
    {
        fprintf(stderr,"Binding a string to SQL statement failed,  Error code = %u\n",
                dwError);
    }
    return dwError;
}

uint32_t
gpmgmt_sql_step_sql(
    sqlite3_stmt *hs
    )
{
    uint32_t dwError = 0;

    dwError = sqlite3_step(hs);
    if (dwError == SQLITE_DONE)
    {
        dwError = 0;
    }

    return dwError;
}

uint32_t
gpmgmt_sql_get_column_int(
    sqlite3_stmt *pSqlStatement,
    const char *pszColumnName,
    uint32_t *pdwValue
    )
{
    uint32_t dwError = 0;
    int indx = -1;
    int nType = 0;

    if(!pSqlStatement || !pszColumnName || !pdwValue)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    indx = gpmgmt_sql_get_column_index_from_name(pSqlStatement, pszColumnName);
    if (indx == -1)
    {
        dwError = SQLITE_NOTFOUND;
    }
    BAIL_ON_PMD_ERROR(dwError);

    nType = sqlite3_column_type(pSqlStatement, indx);
    if ((nType != SQLITE_INTEGER) && (nType != SQLITE_NULL))
    {
        dwError = SQLITE_MISMATCH;
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pdwValue = (uint32_t)sqlite3_column_int(pSqlStatement, indx);

    //fprintf(stdout, "Count is %u \n", *pdwValue);
    //fprintf(stdout, "Count is %d \n", sqlite3_column_int(pSqlStatement, indx));

error:
    if(dwError)
    {
        fprintf(stderr,"SQL column error with Error (%d) \n",dwError);
    }
    return dwError;
}

uint32_t
gpmgmt_sql_get_column_index_from_name(
    sqlite3_stmt *pSqlStatement,
    const char *pszCloumnName
    )
{
    int iCurrColumn = 0;
    int iMaxColumn = 0;
    int indx = -1;

    iMaxColumn = sqlite3_column_count(pSqlStatement);

    while (iCurrColumn < iMaxColumn)
    {
        if (strcmp(pszCloumnName,
                   sqlite3_column_name(pSqlStatement, iCurrColumn)) == 0)
        {
            indx = iCurrColumn;
            break;
        }
        iCurrColumn++;
    }
    return indx;
}

uint32_t
gpmgmt_sql_execute_transaction(
    sqlite3 *pDB,
    const char *sqlStr
    )
{
    sqlite3_stmt *stmt;
    uint32_t dwError = 0;

    if(!pDB || !sqlStr)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = sqlite3_prepare_v2(
        pDB,
        sqlStr,
        -1,
        &stmt,
        0);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = sqlite3_step(stmt);
    if (dwError == SQLITE_DONE)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (stmt)
    {
        sqlite3_finalize(stmt);
    }
    return dwError;

error:
    if(pDB)
    {
        fprintf(stderr, "Executing transaction failed  %s , Error(%u) \n", 
                sqlite3_errmsg(pDB),dwError);
    }
    goto cleanup;
}

uint32_t
gpmgmt_sql_begin_transaction(
    sqlite3 *pDB)
{
    uint32_t dwError = 0;

    if(!pDB)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = sqlite3_exec(
        pDB,
        "BEGIN TRANSACTION",
        NULL,
        NULL,
        NULL);

error:
    if(dwError && pDB)
    {
        fprintf(stderr,"Beginning transaction failed with msg %s, Error (%d) \n",
                        sqlite3_errmsg(pDB),dwError);
    }
    return dwError;
}

uint32_t
gpmgmt_sql_commit_transaction(
    sqlite3 *pDB)
{
    uint32_t dwError = 0;

    if(!pDB)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = sqlite3_exec(
        pDB,
        "COMMIT",
        NULL,
        NULL,
        NULL);

error:
    if(dwError && pDB)
    {
        fprintf(stderr,"Commit transaction failed with msg %s, Error (%d) \n",
                        sqlite3_errmsg(pDB),dwError);
    }
    return dwError;
}

void gpmgmt_sql_database_close(
    sqlite3 *pDB)
{
    sqlite3_close(pDB);
}

uint32_t
gpmgmt_sql_rollback_transaction(
    sqlite3 *pDB)
{
    uint32_t dwError = 0;

    if(!pDB)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = sqlite3_exec(
        pDB,
        "ROLLBACK",
        NULL,
        NULL,
        NULL);

error:
    if(dwError && pDB)
    {
        fprintf(stderr,"Rollback transaction failed with, %s, Error (%d)\n",
                        sqlite3_errmsg(pDB),dwError);
    }
    return dwError;
}

uint32_t
gpmgmt_sql_add_log(
    sqlite3 *pDb,
    const PPMD_POLICY_LOG pLogEntry)
{
    uint32_t dwError = 0;
    bool bInTx = false;
    sqlite3_stmt *pDbQuery = NULL;

    if (!pDb || !pLogEntry)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    char szQuery[] =
        "INSERT INTO LogsTable ("
        " IPAddress,"
        " Time,"
        " LogType,"
        " PolicyName,"
        " IsSuccessful,"
        " ErrorStr)"
        " VALUES("
        " :ipaddress,"
        " :time,"
        " :logtype,"
        " :policyname,"
        " :issuccessful,"
        " :errorstr);";

    dwError = sqlite3_prepare_v2(
        pDb,
        szQuery,
        -1,
        &pDbQuery,
        NULL);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_begin_transaction(pDb);
    BAIL_ON_PMD_ERROR(dwError);

    bInTx = TRUE;

    /* dwError = gpmgmt_sql_bind_dword(pDbQuery,
                                     ":logid",
                                     pLogEntry->dLogID);
    BAIL_ON_PMD_ERROR(dwError);*/

    dwError = gpmgmt_sql_bind_string(pDbQuery,
                                     ":ipaddress",
                                     pLogEntry->pszIPAddress);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_bind_string(pDbQuery,
                                     ":time",
                                     pLogEntry->pszTime);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_bind_string(pDbQuery,
                                     ":logtype",
                                     pLogEntry->pszLogType);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_bind_string(pDbQuery,
                                     ":policyname",
                                     pLogEntry->pszPolicyName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_bind_string(pDbQuery,
                                     ":issuccessful",
                                     pLogEntry->pszIsSuccessful);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_bind_string(pDbQuery,
                                     ":errorstr",
                                     pLogEntry->pszErrorStr);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_step_sql(pDbQuery);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_commit_transaction(pDb);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pDbQuery)
    {
        sqlite3_reset(pDbQuery);
    }
    return dwError;

error:
    if (pDb)
    {
        fprintf(stderr, "Inserting the log in to the table failed  %s\n",
                         sqlite3_errmsg(pDb));
    }
    if (pDb && bInTx)
    {
        gpmgmt_sql_rollback_transaction(pDb);
    }

    goto cleanup;
}

uint32_t
gpmgmt_sql_query_all_logs(
    sqlite3 *pDb,
    PPMD_POLICY_LOG *ppLogEntry,
    uint32_t *pdwCount)
{
    uint32_t dwError = 0;
    uint32_t dwDbStatus = 0;
    PPMD_POLICY_LOG pLogEntry = NULL;
    PPMD_POLICY_LOG pLogEntryHead = NULL;
    uint32_t iEntry = 0;
    uint32_t dwEntriesAvailable = 0;
    sqlite3_stmt *pDbQuery = NULL;

    if(!pDb || !ppLogEntry || !pdwCount )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    CHAR szQuery[] = "SELECT "
                     " LogID as logid,"
                     " IPAddress as ipaddress,"
                     " Time as time,"
                     " LogType as logtype,"
                     " PolicyName as policyname,"
                     " IsSuccessful as issuccessful,"
                     " ErrorStr as errorstr"
                     " FROM LogsTable;";

    dwError = sqlite3_prepare_v2(
        pDb,
        szQuery,
        -1,
        &pDbQuery,
        NULL);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_log_count(pDb,
                                       NULL,
                                       &dwEntriesAvailable);
    fprintf(stdout, "The number of logs are %u \n", dwEntriesAvailable);

    dwDbStatus = gpmgmt_sql_step_sql(pDbQuery);

    while (dwDbStatus == SQLITE_ROW)
    {
        if (!pLogEntryHead)
        {
            dwError = gpmgmt_sql_copy_row(pDbQuery, &pLogEntry);
            BAIL_ON_PMD_ERROR(dwError);
            pLogEntry->counter = iEntry;
            iEntry++;
            pLogEntryHead = pLogEntry;
        }
        else
        {
            dwError = gpmgmt_sql_copy_row(pDbQuery, &(pLogEntry->pNext));
            gpmgmt_sql_print_logs(pLogEntry->pNext);
            BAIL_ON_PMD_ERROR(dwError);
            iEntry++;

            pLogEntry->counter = iEntry;

            pLogEntry = pLogEntry->pNext;
        }
        //fprintf(stdout, "Processing log number %u/%u \n", iEntry, dwEntriesAvailable);

        dwDbStatus = gpmgmt_sql_step_sql(pDbQuery);
    }

    *ppLogEntry = pLogEntryHead;
    *pdwCount = iEntry;

cleanup:

    if (pDbQuery)
    {
        sqlite3_reset(pDbQuery);
    }

    return dwError;

error:
    if (pDb)
    {
        fprintf(stderr, "Getting the logs from the table failed  %s, Error code %d \n",
                        sqlite3_errmsg(pDb),dwError);
    }
    if (ppLogEntry)
    {
        *ppLogEntry = NULL;
    }
    *pdwCount = 0;

    if (pLogEntryHead)
    {
        gpmgmt_sql_free_log_entry(pLogEntryHead);
    }

    goto cleanup;
}

uint32_t
gpmgmt_sql_get_log_count(
    sqlite3 *pDb,
    const char *pszIsSuccessful,
    uint32_t *pdwCount)
{
#define MAX_QUERY 512
    char *pszQuery = "SELECT COUNT(*) AS TotalLogCount FROM LogsTable";
    char *pszWhereCondition = " WHERE IsSuccessful = :issuccessful ;";
    char pszFinalQuery[MAX_QUERY] = {
        0,
    };
    uint32_t dwError = 0;
    uint32_t dwEntriesAvailable = 0;
    uint32_t dwDbStatus = 0;
    sqlite3_stmt *pDbQuery = NULL;

    if(!pDb || !pszIsSuccessful || !pdwCount)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    strncat(pszFinalQuery, pszQuery, MAX_QUERY);
    if (pszIsSuccessful != NULL)
    {
        strncat(pszFinalQuery, pszWhereCondition, MAX_QUERY);
    }

    dwError = sqlite3_prepare_v2(
        pDb,
        pszFinalQuery,
        -1,
        &pDbQuery,
        NULL);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = sqlite3_bind_text(
        pDbQuery,
        1,
        pszIsSuccessful,
        -1,
        SQLITE_TRANSIENT);
    BAIL_ON_PMD_ERROR(dwError);

    dwDbStatus = gpmgmt_sql_step_sql(pDbQuery);
    if ((dwDbStatus != SQLITE_DONE) &&
        (dwDbStatus != SQLITE_ROW))
    {
        dwError = dwDbStatus;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = gpmgmt_sql_get_column_int(
        pDbQuery,
        "TotalLogCount",
        &dwEntriesAvailable);
    BAIL_ON_PMD_ERROR(dwError);

    *pdwCount = dwEntriesAvailable;

cleanup:
    if (pDbQuery)
    {
        sqlite3_reset(pDbQuery);
    }

    return dwError;
error:
    if (pDb)
    {
        fprintf(stderr, "Error in getting the log count , %s \n", sqlite3_errmsg(pDb));
    }
    goto cleanup;
}

uint32_t
gpmgmt_sql_copy_row(
    sqlite3_stmt *pSqlStatement,
    PPMD_POLICY_LOG *ppEntry)
{
    uint32_t dwError = 0;
    uint32_t dwSize = 0;
    PPMD_POLICY_LOG pEntry = NULL;

    if(!pSqlStatement || !ppEntry)
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_POLICY_LOG), (void **)&pEntry);
    BAIL_ON_PMD_ERROR(dwError);

    pEntry->dLogID          = 0;
    pEntry->pszIPAddress    = NULL;
    pEntry->pszTime         = NULL;
    pEntry->pszLogType      = NULL;
    pEntry->pszPolicyName   = NULL;
    pEntry->pszIsSuccessful = NULL;
    pEntry->pszErrorStr     = NULL;
    pEntry->pNext           = NULL;


    dwError = gpmgmt_sql_get_column_int(
        pSqlStatement,
        "logid",
        &pEntry->dLogID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_string(
        pSqlStatement,
        "ipaddress",
        &pEntry->pszIPAddress);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_string(
        pSqlStatement,
        "time",
        &pEntry->pszTime);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_string(
        pSqlStatement,
        "logtype",
        &pEntry->pszLogType);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_string(
        pSqlStatement,
        "policyname",
        &pEntry->pszPolicyName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_string(
        pSqlStatement,
        "issuccessful",
        &pEntry->pszIsSuccessful);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = gpmgmt_sql_get_column_string(
        pSqlStatement,
        "errorstr",
        &pEntry->pszErrorStr);
    BAIL_ON_PMD_ERROR(dwError);

    *ppEntry = pEntry;

cleanup:
    return dwError;

error:
    fprintf(stderr,"Error copying SQL result row to the result buffer \n");
    if (ppEntry)
    {
        *ppEntry = NULL;
    }
    if (pEntry)
    {
        gpmgmt_sql_free_log_entry(pEntry);
    }
    goto cleanup;
}

uint32_t
gpmgmt_sql_get_column_string(
    sqlite3_stmt *pSqlStatement,
    const char *pszColumnName,
    char **ppszValue)
{
    uint32_t dwError = 0;
    int indx = -1;
    const char *psztmpValue = NULL;
    int nType = 0;

    if(!pSqlStatement || !pszColumnName || !ppszValue )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    indx = gpmgmt_sql_get_column_index_from_name(pSqlStatement, pszColumnName);
    //fprintf(stdout, "Index of the column name %s is %d \n", pszColumnName, indx);

    if (indx == -1)
    {
        dwError = SQLITE_NOTFOUND;
    }
    BAIL_ON_PMD_ERROR(dwError);

    nType = sqlite3_column_type(pSqlStatement, indx);
    if ((nType != SQLITE_TEXT) && (nType != SQLITE_NULL))
    {
        dwError = SQLITE_MISMATCH;
    }
    BAIL_ON_PMD_ERROR(dwError);

    psztmpValue = (char *)sqlite3_column_text(pSqlStatement, indx);
    if (psztmpValue != NULL)
    {
        dwError = PMDAllocateString(
            psztmpValue,
            ppszValue);
        BAIL_ON_PMD_ERROR(dwError);
    }
    else
    {
        *ppszValue = NULL;
    }

error:
    if(dwError)
    {
        fprintf(stderr,"Getting column string from SQL statement failed,Error code %u \n",dwError);
    }
    return dwError;
}

uint32_t
gpmgmt_sql_bind_dword(
    sqlite3_stmt *pSqlStatement,
    const char *pszParamName,
    uint32_t dwValue)
{
    uint32_t dwError = 0;
    int indx = -1;

    if(!pSqlStatement || !pszParamName )
    {
        dwError = ERROR_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    indx = sqlite3_bind_parameter_index(pSqlStatement, pszParamName);
    // This returns zero when pszParam Name is not found, which is
    // little strange since it means SQLITE_OK :(
    if (indx == 0)
    {
        dwError = SQLITE_NOTFOUND;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = sqlite3_bind_int(
        pSqlStatement,
        indx,
        dwValue);
    BAIL_ON_PMD_ERROR(dwError);

error:
    if(dwError)
    {
        fprintf(stderr,"Binding word to SQL statement failed,Error code %u \n",dwError);
    }
    return dwError;
}

void
gpmgmt_sql_free_log_entry(
    PPMD_POLICY_LOG pLogEntry)
{
    PPMD_POLICY_LOG pLogEntryPrev = NULL;

    while (pLogEntry)
    {
        PMD_SAFE_FREE_MEMORY(pLogEntry->pszIPAddress);
        PMD_SAFE_FREE_MEMORY(pLogEntry->pszTime);
        PMD_SAFE_FREE_MEMORY(pLogEntry->pszLogType);
        PMD_SAFE_FREE_MEMORY(pLogEntry->pszPolicyName);
        PMD_SAFE_FREE_MEMORY(pLogEntry->pszIsSuccessful);
        PMD_SAFE_FREE_MEMORY(pLogEntry->pszErrorStr);

        pLogEntryPrev = pLogEntry;
        pLogEntry = pLogEntry->pNext;
        PMD_SAFE_FREE_MEMORY(pLogEntryPrev);
    }
}

uint32_t
gpmgmt_sql_print_logs(
    PPMD_POLICY_LOG pLogEntry)
{
    uint32_t dwError = 0;
    int count = 20;

    if (!pLogEntry)
        fprintf(stdout, " No logs found \n");

    while (pLogEntry && (count>0))
    {
        count --;
        fprintf(stdout,"Counter is %d \n",pLogEntry->counter);
        fprintf(stdout, "LogID =%u |"
                        "IpAddress = %s |"
                        "Time  = %s |"
                        "Logtype = %s |"
                        "PolicyName = %s |"
                        "IsSuccessful = %s \n"
                        "ErrorString =  %s \n",
                pLogEntry->dLogID,
                pLogEntry->pszIPAddress,
                pLogEntry->pszTime,
                pLogEntry->pszLogType,
                pLogEntry->pszPolicyName,
                pLogEntry->pszIsSuccessful,
                pLogEntry->pszErrorStr);

        pLogEntry = pLogEntry->pNext;
    }

    return dwError;
}
