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

void
print_jwt_parts(
    PJWT_PARTS pParts
    )
{
    fprintf(stdout, "TokenType: %s\n", pParts->pszTokenType);
    fprintf(stdout, "Header: %s\n", pParts->pszHeader);
    fprintf(stdout, "Claims: %s\n", pParts->pszClaims);
    fprintf(stdout, "Signature: %s\n", pParts->pszSignature);
}

void
print_jwt_array(
    const char *pszName,
    PJWT_ARRAY pArray
    )
{
    int i = 0;
    if(!pArray)
    {
        return;
    }
    fprintf(stdout, "%s [", pszName);
    for(i = 0; i < pArray->nCount; ++i)
    {
        fprintf(stdout, "%s%s", pArray->ppszValues[i], ",");
    }
    fprintf(stdout, "]\n");
}

void
print_jwt(
    PJWT pJWT
    )
{
    if(!pJWT)
    {
        return;
    }
    if(pJWT->pHeader)
    {
        fprintf(stdout, "Header\n");
        fprintf(stdout, "\tType: %s\n", pJWT->pHeader->pszType);
        fprintf(stdout, "\tAlg: %s\n", pJWT->pHeader->pszAlg);
        fprintf(stdout, "\n");
    }
    if(pJWT->pClaims)
    {
        fprintf(stdout, "Claims\n");
        fprintf(stdout, "\tSubject: %s\n", pJWT->pClaims->pszSubject);
        print_jwt_array("\tAudience:", pJWT->pClaims->pAudienceArray);
        fprintf(stdout, "\tIssuer: %s\n", pJWT->pClaims->pszIssuer);
        print_jwt_array("\tGroups:", pJWT->pClaims->pGroupsArray);
        fprintf(stdout, "\tTenant: %s\n", pJWT->pClaims->pszTenant);
    }
}

uint32_t
process_oidc_auth_header(
    PREST_REQUEST pRequest,
    PJWT_ERROR *ppError
    )
{
    uint32_t dwError = 0;
    const char *pszBearer = "Bearer ";
    char *pszBase64 = NULL;
    char *pszAuth = NULL;
    char *pszDecode = NULL;
    int nLength = 0;
    PJWT_PARTS pJWTParts = NULL;
    PJWT pJWT = NULL;
    PJWT_ERROR pError = NULL;

    if(!pRequest)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = VmRESTGetHttpHeader(pRequest, "Authorization", &pszAuth);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pszAuth)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_jwt_parts(pszAuth, &pJWTParts);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_jwt(pJWTParts, &pJWT);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = validate_jwt(pJWT, &pError);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    free_jwt_error(pError);
    free_jwt_parts(pJWTParts);
    free_jwt(pJWT);
    return dwError;

error:
    if(dwError == ENOENT)
    {
        dwError = 0;
    }
    if(ppError)
    {
        *ppError = pError;
        pError = NULL;
    }
    goto cleanup;
}

uint32_t
get_jwt_parts(
    const char *pszAuth,
    PJWT_PARTS *ppParts
    )
{
    uint32_t dwError = 0;
    PJWT_PARTS pParts = NULL;
    char **ppszArray = NULL;
    int nCount = 0;
    int nDecodeLength = 0;
    char *pszTemp = NULL;

    if(IsNullOrEmptyString(pszAuth) || !ppParts)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(JWT_PARTS), (void **)&pParts);
    BAIL_ON_PMD_ERROR(dwError);

    pszTemp = strstr(pszAuth, AUTH_BEARER);
    if(!pszTemp)
    {
        fprintf(stderr,
                "Did not start with %s. Not processing\n",
                AUTH_BEARER);
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszTemp = pszTemp + strlen(AUTH_BEARER);

    dwError = PMDAllocateString(AUTH_BEARER, &pParts->pszTokenType);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = make_array_from_string(pszTemp, ".", &ppszArray, &nCount);
    BAIL_ON_PMD_ERROR(dwError);

    if(nCount != 3)
    {
        fprintf(stderr,
                "Found %d parts instead of 3. Not processing\n",
                nCount);
        dwError = EINVAL;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = base64_decode(ppszArray[0], &pParts->pszHeader, &nDecodeLength);
    BAIL_ON_PMD_ERROR(dwError);


    dwError = base64_decode(ppszArray[1], &pParts->pszClaims, &nDecodeLength);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = base64_decode(ppszArray[2],
                            &pParts->pszSignature,
                            &nDecodeLength);
    //TODO: Investigate signature parse error after main workflow is validated.
    dwError = 0;
    BAIL_ON_PMD_ERROR(dwError);

    *ppParts = pParts;

cleanup:
    PMDFreeStringArrayWithCount(ppszArray, nCount);
    return dwError;

error:
    if(ppParts)
    {
        *ppParts = NULL;
    }
    free_jwt_parts(pParts);
    goto cleanup;
}

uint32_t
get_jwt_header(
    const char *pszJson,
    PJWT_HEADER *ppHeader
    )
{
    uint32_t dwError = 0;
    json_t *pRoot = NULL;
    PJWT_HEADER pHeader = NULL;

    dwError = get_json_object_from_string(pszJson, &pRoot);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(JWT_HEADER), (void **)&pHeader);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "type", &pHeader->pszType);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "alg", &pHeader->pszAlg);
    BAIL_ON_PMD_ERROR(dwError);

    *ppHeader = pHeader;
cleanup:
    if(pRoot)
    {
        json_decref(pRoot);
    }
    return dwError;

error:
    if(ppHeader)
    {
        *ppHeader = NULL;
    }
    free_jwt_header(pHeader);
    goto cleanup;
}

void
free_jwt_array(
    PJWT_ARRAY pArray
    )
{
    if(!pArray)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pArray);
}

uint32_t
get_jwt_array(
    json_t *pRoot,
    const char *pszKey,
    PJWT_ARRAY *ppArray
    )
{
    uint32_t dwError = 0;
    PJWT_ARRAY pArray = NULL;
    json_t *pValue = NULL;
    json_t *pJsonArray = NULL;
    int i = 0;

    if(!pRoot || IsNullOrEmptyString(pszKey) || !ppArray)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(JWT_ARRAY), (void **)&pArray);
    BAIL_ON_PMD_ERROR(dwError);

    pJsonArray = json_object_get(pRoot, pszKey);
    if(!pJsonArray)
    {
        dwError = ENOENT;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pArray->nCount = json_array_size(pJsonArray);

    dwError = PMDAllocateMemory(sizeof(char **), (void **)&pArray->ppszValues);
    BAIL_ON_PMD_ERROR(dwError);

    json_array_foreach(pJsonArray, i, pValue)
    {
        const char *pszValue = json_string_value(pValue);
        if(IsNullOrEmptyString(pszValue))
        {
            dwError = ENOENT;
            BAIL_ON_PMD_ERROR(dwError);
        }
        dwError = PMDAllocateString(pszValue, &pArray->ppszValues[i]);
        BAIL_ON_PMD_ERROR(dwError);

        json_decref(pValue);
    }

    *ppArray = pArray;

cleanup:
    if(pJsonArray)
    {
        //json_decref(pJsonArray);
    }
    return dwError;

error:
    if(ppArray)
    {
        *ppArray = NULL;
    }
    free_jwt_array(pArray);
    goto cleanup;
}

uint32_t
get_jwt_claims(
    const char *pszJson,
    PJWT_CLAIMS *ppClaims
    )
{
    uint32_t dwError = 0;
    json_t *pRoot = NULL;
    PJWT_CLAIMS pClaims = NULL;

    dwError = get_json_object_from_string(pszJson, &pRoot);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(sizeof(JWT_CLAIMS), (void **)&pClaims);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "sub", &pClaims->pszSubject);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_jwt_array(pRoot, "aud", &pClaims->pAudienceArray);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "iss", &pClaims->pszIssuer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "token_class", &pClaims->pszTokenClass);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "token_type", &pClaims->pszTokenType);
    BAIL_ON_PMD_ERROR(dwError);

    pClaims->dwExpiry = json_integer_value(json_object_get(pRoot, "exp"));
    BAIL_ON_PMD_ERROR(dwError);

    pClaims->dwIssuedAt = json_integer_value(json_object_get(pRoot, "iat"));
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_jwt_array(pRoot, "groups", &pClaims->pGroupsArray);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "jti", &pClaims->pszJWTID);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = json_get_opt_string_value(pRoot, "tenant", &pClaims->pszTenant);
    BAIL_ON_PMD_ERROR(dwError);

    *ppClaims = pClaims;
cleanup:
    if(pRoot)
    {
        //json_decref(pRoot);
    }
    return dwError;

error:
    if(ppClaims)
    {
        *ppClaims = NULL;
    }
    free_jwt_claims(pClaims);
    goto cleanup;
}

uint32_t
get_jwt(
    PJWT_PARTS pParts,
    PJWT *ppJWT
    )
{
    uint32_t dwError = 0;
    PJWT pJWT = NULL;

    if(!pParts || !ppJWT)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(JWT), (void **)&pJWT);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_jwt_header(pParts->pszHeader, &pJWT->pHeader);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_jwt_claims(pParts->pszClaims, &pJWT->pClaims);
    BAIL_ON_PMD_ERROR(dwError);

    *ppJWT = pJWT;

cleanup:
    return dwError;

error:
    if(ppJWT)
    {
        *ppJWT = NULL;
    }
    free_jwt(pJWT);
    goto cleanup;
}

#define PMD_TIME_INSENSITIVE

uint32_t
validate_jwt(
    PJWT pJWT,
    PJWT_ERROR *ppError
    )
{
    uint32_t dwError = 0;
    time_t dwTime = 0;
    char *pszLWAdminGroup = NULL;
    PJWT_ERROR pError = NULL;

    if(!pJWT)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(JWT_ERROR), (void **)&pError);
    BAIL_ON_PMD_ERROR(dwError);

//flag to do quick tests with token reuse.
#ifndef PMD_TIME_INSENSITIVE
    //validate expiry date
    dwTime = time(NULL);
    if(dwTime > pJWT->pClaims->dwExpiry)
    {
        pError->nStatus= HTTP_FORBIDDEN;
        dwError = PMDAllocateStringPrintf(
                      &pError->pszError,
                      "Token expired.");
        BAIL_ON_PMD_ERROR(dwError);

        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    //issued at must not be in the future
    if(dwTime > pJWT->pClaims->dwIssuedAt)
    {
        pError->nStatus = HTTP_FORBIDDEN;
        dwError = PMDAllocateStringPrintf(
                      &pError->pszError,
                      "Token issued at date is in the future.");
        BAIL_ON_PMD_ERROR(dwError);

        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
#endif

    //this server should be in audience
    dwError = find_in_array(pJWT->pClaims->pAudienceArray->ppszValues,
                     pJWT->pClaims->pAudienceArray->nCount,
                     PMD_OAUTH_AUD);
    if(dwError == ENOENT)
    {
        pError->nStatus = HTTP_FORBIDDEN;
        dwError = PMDAllocateStringPrintf(
                      &pError->pszError,
                      "Audience does not have expected entries.");
        BAIL_ON_PMD_ERROR(dwError);

        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);
    //must be in administrators group
    dwError = PMDAllocateStringPrintf(&pszLWAdminGroup,
                                      "%s\\%s",
                                      pJWT->pClaims->pszTenant,
                                      LW_ADMIN_GROUP_NAME);
    BAIL_ON_PMD_ERROR(dwError);
    dwError = find_in_array(pJWT->pClaims->pGroupsArray->ppszValues,
                     pJWT->pClaims->pGroupsArray->nCount,
                     pszLWAdminGroup);
    if(dwError == ENOENT)
    {
        pError->nStatus = HTTP_FORBIDDEN;
        dwError = PMDAllocateStringPrintf(
                      &pError->pszError,
                      "Not an administrators group member.");
        BAIL_ON_PMD_ERROR(dwError);

        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);


cleanup:
    free_jwt_error(pError);
    PMD_SAFE_FREE_MEMORY(pszLWAdminGroup);
    return dwError;

error:
    if(ppError)
    {
        *ppError = pError;
        pError = NULL;
    }
    goto cleanup;
}

void
free_jwt_parts(
    PJWT_PARTS pParts
    )
{
    if(!pParts)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pParts->pszTokenType);
    PMD_SAFE_FREE_MEMORY(pParts);
}

void
free_jwt_header(
    PJWT_HEADER pHeader
    )
{
    if(!pHeader)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pHeader->pszType);
    PMD_SAFE_FREE_MEMORY(pHeader->pszAlg);
    PMD_SAFE_FREE_MEMORY(pHeader);
}

void
free_jwt_claims(
    PJWT_CLAIMS pClaims
    )
{
    if(!pClaims)
    {
        return;
    }
    PMD_SAFE_FREE_MEMORY(pClaims->pszSubject);
    PMD_SAFE_FREE_MEMORY(pClaims->pszIssuer);
    PMD_SAFE_FREE_MEMORY(pClaims->pszTenant);
    PMD_SAFE_FREE_MEMORY(pClaims);
}

void
free_jwt(
    PJWT pJWT
    )
{
    if(!pJWT)
    {
        return;
    }
    free_jwt_header(pJWT->pHeader);
    free_jwt_claims(pJWT->pClaims);
    PMD_SAFE_FREE_MEMORY(pJWT);
}

void
free_jwt_error(
    PJWT_ERROR pError
    )
{
    if(pError)
    {
        PMD_SAFE_FREE_MEMORY(pError->pszError);
        PMD_SAFE_FREE_MEMORY(pError);
    }
}
