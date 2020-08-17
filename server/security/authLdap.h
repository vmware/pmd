/*
 * Copyright © 2020-2021 VMware, Inc.  All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the “License”); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS, without
 * warranties or conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef AUTHLDAP_H_
#define AUTHLDAP_H_

typedef struct _PMDDIR_CONNECTION
{
    LDAP* pLd;
    char *pszDomain;
} PMDDIR_CONNECTION;

typedef struct _PMDDIR_CONNECTION* PPMDDIR_CONNECTION;

uint32_t
PmdDirConnectionOpen(
    const char *pszLdapURI,
    const char *pszDomain,
    const char *pszUsername,
    const char *pszPassword,
    PPMDDIR_CONNECTION* ppConnection
    );

VOID
PmdDirConnectionClose(
    PPMDDIR_CONNECTION pConnection
    );

uint32_t
PmdDirGetMemberships(
    PPMDDIR_CONNECTION pConnection,
    const char *pszUPNName,
    char ***pppszMemberships,
    uint32_t *pdwMemberships
    );

VOID
PmdDirFreeMemberships(
    char **ppszMemberships,
    uint32_t dwMemberships
    );

#endif /* AUTHLDAP_H_ */



