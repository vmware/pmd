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

#define ERROR_PMD_CLI_BASE                    800
#define ERROR_PMD_CLI_CONNECTION              (ERROR_PMD_CLI_BASE + 1)
#define ERROR_PMD_CLI_NO_MATCH                (ERROR_PMD_CLI_BASE + 2)
#define ERROR_PMD_CLI_INVALID_ARGUMENT        (ERROR_PMD_CLI_BASE + 3)
#define ERROR_PMD_CLI_CLEAN_REQUIRES_OPTION   (ERROR_PMD_CLI_BASE + 4)
#define ERROR_PMD_CLI_NOT_ENOUGH_ARGS         (ERROR_PMD_CLI_BASE + 5)
#define ERROR_PMD_CLI_NOTHING_TO_DO           (ERROR_PMD_CLI_BASE + 6)
#define ERROR_PMD_CLI_CHECKLOCAL_EXPECT_DIR   (ERROR_PMD_CLI_BASE + 7)
#define ERROR_PMD_CLI_PROVIDES_EXPECT_ARG     (ERROR_PMD_CLI_BASE + 8)
#define ERROR_PMD_CLI_OPTION_NAME_INVALID     (ERROR_PMD_CLI_BASE + 9)
#define ERROR_PMD_CLI_OPTION_ARG_REQUIRED     (ERROR_PMD_CLI_BASE + 10)
#define ERROR_PMD_CLI_OPTION_ARG_UNEXPECTED   (ERROR_PMD_CLI_BASE + 11)
#define ERROR_PMD_CLI_SERVER_NAME_REQUIRED    (ERROR_PMD_CLI_BASE + 12)
#define ERROR_PMD_CLI_SYNCTO_REQUIRED         (ERROR_PMD_CLI_BASE + 13)
#define ERROR_PMD_CLI_NO_SUCH_OPTION          (ERROR_PMD_CLI_BASE + 14)

//main cli options
#define OPT_SERVERNAME      "servername"
#define OPT_USERNAME        "user"
#define OPT_DOMAINNAME      "domain"
#define OPT_PASSWORD        "password"
#define OPT_SPN             "spn"

#define IsNullOrEmptyString(str) (!(str) || !(*str))

#define BAIL_ON_CLI_ERROR(unError) \
    do {                                                           \
        if (unError)                                               \
        {                                                          \
            goto error;                                            \
        }                                                          \
    } while(0)

#define PMD_CLI_SAFE_FREE_MEMORY(pMemory) \
    do {                                                           \
        if (pMemory) {                                             \
            PMDFreeMemory(pMemory);                                \
        }                                                          \
    } while(0)

#define PMD_CLI_SAFE_FREE_STRINGARRAY(ppArray) \
    do {                                                           \
        if (ppArray) { \
        PMDFreeStringArray(ppArray); \
        }                                                          \
    } while(0)

#define PMD_CLI_ERROR_TABLE \
{ \
    {ERROR_PMD_CLI_BASE,                    "ERROR_PMD_CLI_BASE",                   "Generic base error"}, \
    {ERROR_PMD_CLI_CONNECTION,              "ERROR_PMD_CLI_CONNECTION",             "RPC server connection error"}, \
    {ERROR_PMD_CLI_NO_MATCH,                "ERROR_PMD_CLI_NO_MATCH",               "There was no match for the search"}, \
    {ERROR_PMD_CLI_INVALID_ARGUMENT,        "ERROR_PMD_CLI_INVALID_ARGUMENT",       "Invalid argument"}, \
    {ERROR_PMD_CLI_CLEAN_REQUIRES_OPTION,   "ERROR_PMD_CLI_CLEAN_REQUIRES_OPTION",  "Clean requires an option: packages, metadata, dbcache, plugins, expire-cache, rpmdb, all"}, \
    {ERROR_PMD_CLI_NOT_ENOUGH_ARGS,         "ERROR_PMD_CLI_NOT_ENOUGH_ARGS",        "The command line parser could not continue. Expected at least one argument"}, \
    {ERROR_PMD_CLI_NOTHING_TO_DO,           "ERROR_PMD_CLI_NOTHING_TO_DO",          "Nothing to do"}, \
    {ERROR_PMD_CLI_OPTION_NAME_INVALID,     "ERROR_PMD_CLI_OPTION_NAME_INVALID",    "Command line error: option is invalid."}, \
    {ERROR_PMD_CLI_OPTION_ARG_REQUIRED,     "ERROR_PMD_CLI_OPTION_ARG_REQUIRED",    "Command line error: expected one argument"}, \
    {ERROR_PMD_CLI_OPTION_ARG_UNEXPECTED,   "ERROR_PMD_CLI_OPTION_ARG_UNEXPECTED",  "Command line error: argument was unexpected"}, \
    {ERROR_PMD_CLI_CHECKLOCAL_EXPECT_DIR,   "ERROR_PMD_CLI_CHECKLOCAL_EXPECT_DIR",  "check-local requires path to rpm directory as a parameter"}, \
    {ERROR_PMD_CLI_PROVIDES_EXPECT_ARG,     "ERROR_PMD_CLI_PROVIDES_EXPECT_ARG",    "Need an item to match"}, \
    {ERROR_PMD_CLI_SERVER_NAME_REQUIRED,    "ERROR_PMD_CLI_SERVER_NAME_REQUIRED",   "Server name or ip address must be specified. Please specify using --server."}, \
    {ERROR_PMD_CLI_SYNCTO_REQUIRED,         "ERROR_PMD_CLI_SYNCTO_REQUIRED",        "Please specify a hash to sync to."}, \
    {ERROR_PMD_CLI_NO_SUCH_OPTION,          "ERROR_PMD_CLI_NO_SUCH_OPTION",         "Specified option is invalid."}, \
};
