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

typedef struct _REST_MODULE_ENTRY_
{
    PREST_MODULE pRestModule;
    PREST_PROCESSOR pRestProcessor;
    struct _REST_MODULE_ENTRY_ *pNext;
}REST_MODULE_ENTRY, *PREST_MODULE_ENTRY;

typedef struct _JWT_PARTS_
{
    char *pszTokenType;
    char *pszHeader;
    char *pszClaims;
    char *pszSignature;
}JWT_PARTS, *PJWT_PARTS;

typedef struct _JWT_HEADER_
{
    char *pszType;
    char *pszAlg;
}JWT_HEADER, *PJWT_HEADER;

typedef struct _JWT_ARRAY_
{
    char **ppszValues;
    int nCount;
}JWT_ARRAY, *PJWT_ARRAY;

typedef struct _JWT_CLAIMS_
{
    char *pszSubject;
    PJWT_ARRAY pAudienceArray;
    PJWT_ARRAY pScopeArray;
    char *pszIssuer;
    PJWT_ARRAY pGroupsArray;
    char *pszTokenClass;
    char *pszTokenType;
    uint32_t dwExpiry;
    uint32_t dwIssuedAt;
    char *pszJWTID;
    char *pszTenant;
}JWT_CLAIMS, *PJWT_CLAIMS;

typedef struct _JWT_
{
    PJWT_HEADER pHeader;
    PJWT_CLAIMS pClaims;
}JWT, *PJWT;

typedef struct _JWT_ERROR_
{
    int nStatus;
    char *pszError;
}JWT_ERROR, *PJWT_ERROR;
