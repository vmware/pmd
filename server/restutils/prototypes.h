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
//openidconnect.c
uint32_t
process_oidc_auth_header(
    PREST_REQUEST pRequest,
    PJWT_ERROR *ppError
    );

uint32_t
get_jwt_parts(
    const char *pszAuth,
    PJWT_PARTS *ppParts
    );

uint32_t
get_jwt(
    PJWT_PARTS pParts,
    PJWT *ppJWT
    );

uint32_t
validate_jwt(
    PJWT pJWT,
    PJWT_ERROR *ppError
    );

uint32_t
make_error(
    int nStatus,
    PJWT_ERROR *ppError
    );

void
free_jwt_header(
    PJWT_HEADER pHeader
    );

void
free_jwt_claims(
    PJWT_CLAIMS pClaims
    );

void
free_jwt(
    PJWT pJWT
    );

void
free_jwt_parts(
    PJWT_PARTS pParts
    );

void
free_jwt_error(
    PJWT_ERROR pError
    );
//restapidef.c
uint32_t
load_api_def_from_string(
    const char *pszString,
    PREST_API_DEF *ppApiDef
    );

uint32_t
load_api_def_from_file(
    const char *pszFile,
    PREST_API_DEF *ppApiDef
    );

uint32_t
load_modules(
    json_t *pRoot,
    PREST_API_MODULE *ppApiModules
    );

uint32_t
load_endpoints(
    json_t *pRoot,
    const char *pszBasePath,
    PREST_API_MODULE pApiModules
    );

uint32_t
load_parameters(
    json_t *pMethod,
    PREST_API_PARAM *ppParam
    );

uint32_t
module_add_endpoint(
    PREST_API_MODULE pModule,
    PREST_API_ENDPOINT pEndPoint
    );

uint32_t
find_tagged_module(
    json_t *pPath,
    PREST_API_MODULE pModules,
    PREST_API_MODULE *ppModule
    );

uint32_t
find_module_by_name(
    const char *pszName,
    PREST_API_MODULE pModules,
    PREST_API_MODULE *ppModule
    );

uint32_t
find_endpoint_by_name(
    const char *pszName,
    PREST_API_ENDPOINT pEndPoints,
    PREST_API_ENDPOINT *ppEndPoint
    );

uint32_t
find_module_impl_by_name(
    const char *pszName,
    PREST_MODULE pModules,
    PREST_MODULE *ppModule
    );

uint32_t
apispec_is_integer(
    const char *pszValue,
    int *pnValid
    );

uint32_t
apispec_check_param(
    PREST_API_PARAM pParam,
    const char *pszValue,
    int *pnValid
    );

uint32_t
apispec_get_required_params(
    PREST_API_METHOD pMethod,
    PREST_API_PARAM **pppRequiredParams,
    int *pnRequiredParamsCount
    );

uint32_t
apispec_find_handler(
    PREST_API_DEF pApiDef,
    const char *pszEndPoint,
    const char *pszMethod,
    PREST_API_METHOD *ppMethod
    );

uint32_t
map_rest_type(
    const char *pszType,
    RESTPARAMTYPE *pnType
    );

uint32_t
map_rest_method(
    const char *pszMethod,
    RESTMETHOD *pnMethod
    );

void
print_api_def(
    PREST_API_DEF pApiDef
    );

uint32_t
map_api_impl(
    PREST_API_DEF pApiDef,
    PMODULE_REG_MAP pRegMap
    );

uint32_t
map_module_impl(
    PREST_API_MODULE pModule,
    PREST_MODULE pModuleImpl
    );

void
free_api_def(
    PREST_API_DEF pApiDef
    );

//restauth.c
uint32_t
process_auth(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    );

//restutils.c
uint32_t
rest_register_api_spec(
    PREST_API_DEF pApiDef,
    PREST_PROCESSOR *ppRestProcessor
    );

uint32_t
rest_get_keyvalues(
    PREST_REQUEST pRequest,
    uint32_t dwCount,
    PKEYVALUE *ppKeyValue
    );

uint32_t
rest_method(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse,
    uint32_t paramsCount
    );
//
uint32_t
base64_encode(
    const unsigned char* pszInput,
    const size_t nInputLength,
    char** ppszOutput
    );

uint32_t
base64_decode(
    const char* pszInput,
    char** ppszOutput,
    int *pnLength
    );

uint32_t
split_user_and_pass(
    const char* pszUserPass,
    char** ppszUser,
    char** ppszPass
    );

uint32_t
pmd_check_password(
    const char* user_name,
    const char* password,
    uint32_t* valid
    );

//restnegauth.c
uint32_t
request_negotiate_auth(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse,
    const char* pszToken
    );

uint32_t
make_negotiate_string(
    gss_buffer_desc *pBuffer,
    PSTR *ppszNegotiate
    );

uint32_t
verify_krb_auth(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    );

//restbasicauth.c
uint32_t
request_basic_auth(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    );

uint32_t
verify_basic_auth(
    PREST_REQUEST pRequest,
    PREST_RESPONSE* ppResponse
    );
