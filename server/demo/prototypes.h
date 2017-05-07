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
//demoapi.c
uint32_t
demo_version(
    char **ppszVersion
    );

uint32_t
demo_isprime(
    int nNumToCheck,
    int *pnIsPrime
    );

uint32_t
demo_primes(
    int nStart,
    int nCount,
    int **ppnPrimes,
    int *pnPrimeCount
    );

//demorestapi.c
uint32_t
demo_rest_get_registration(
    PREST_MODULE *ppRestModule
    );

uint32_t
demo_rest_isprime_json(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
demo_rest_primes_json(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
demo_rest_get_fav_json(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
demo_rest_set_fav_json(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
demo_rest_update_fav_json(
    void *pInputJson,
    void **ppOutputJson
    );

uint32_t
demo_rest_delete_fav_json(
    void *pInputJson,
    void **ppOutputJson
    );
