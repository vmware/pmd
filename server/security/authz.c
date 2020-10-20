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

#define FQDN_SEPARATOR '.'

static
uint32_t
gid_from_group_name(
    const char* group_name,
    gid_t* gid
    )
{
    uint32_t dwError = 0;
    struct group* gr = getgrnam(group_name);
    if(gr == NULL)
    {
        if(errno == EACCES)
        {
            fprintf(stderr,
                    "Access denied attempting to get group name: %s",
                    group_name);
            dwError = ERROR_PMD_ACCESS_DENIED;
        }
        else
        {
            dwError = ERROR_PMD_NO_DATA;
        }
        BAIL_ON_PMD_ERROR(dwError);
    }
    *gid = gr->gr_gid;
cleanup:
    return dwError;

error:
    goto cleanup;

}

static
uint32_t
member_of_groups(
    gid_t group_id,
    gid_t *groups,
    uint32_t num_groups)
{
    uint32_t is_member = 0;
    int i = 0;
    for( ; i < num_groups; i++)
    {
        if( groups[i] == group_id)
        {
            is_member = 1;
        }
    }
    return is_member;
}

static
uint32_t
get_local_memberships(
    const char* user_name,
    gid_t gid,
    gid_t** memberships,
    uint32_t* num_memberships
    )
{
    uint32_t dwError = 0;
    gid_t firstgroup;
    gid_t *groups;
    int ngroups = 1;
    if(getgrouplist(user_name, gid, &firstgroup, &ngroups) == -1)
    {
        dwError = PMDAllocateMemory((ngroups * sizeof (gid_t)), (void**)&groups);
        BAIL_ON_PMD_ERROR(dwError);
        getgrouplist(user_name, gid,  groups, &ngroups);
    }
    else
    {
        dwError = PMDAllocateMemory((ngroups * sizeof (gid_t)), (void**)&groups);
        BAIL_ON_PMD_ERROR(dwError);
        groups[0] = firstgroup;
    }
    *memberships = groups;
    *num_memberships = ngroups;
cleanup:
    return dwError;
error:
    PMDFreeMemory(groups);
    goto cleanup;
}

static
uint32_t
memberships_from_uid(
    uid_t  uid,
    gid_t** memberships,
    uint32_t* num_memberships)
{
    uint32_t dwError = 0;

    struct passwd *pw;
    gid_t* groups = NULL;
    uint32_t ngroups;
    pw = getpwuid(uid);
    if (pw == NULL)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = get_local_memberships(pw->pw_name,
                 pw->pw_gid, &groups,
                 &ngroups);
    BAIL_ON_PMD_ERROR(dwError);
    *memberships = groups;
    *num_memberships = ngroups;
cleanup:
    return dwError;
error:
    goto cleanup;

}
static
uint32_t
memberships_from_user_name(
    const char* user,
    gid_t** memberships,
    uint32_t* num_memberships)
{
    uint32_t dwError = 0;
    struct passwd *pw;
    gid_t* groups = NULL;
    pw = getpwnam(user);
    if (pw == NULL)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = get_local_memberships(pw->pw_name,
                 pw->pw_gid, &groups,
                 num_memberships);
    BAIL_ON_PMD_ERROR(dwError);
    *memberships = groups;
cleanup:
    return dwError;
error:
    PMDFreeMemory(groups);
    goto cleanup;

}

uint32_t
pmd_check_password(
    const char* pszUserName,
    const char* pszPassword,
    uint32_t* pnValid)
{
    uint32_t dwError = 0;
    struct passwd* pPassword;
    struct spwd *psPwd;
    const char* pszSalt;
    char *pszEncrypted = NULL;
    int nValid = 0;

    if(IsNullOrEmptyString(pszUserName) ||
       IsNullOrEmptyString(pszPassword) ||
       !pnValid)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPassword = getpwnam(pszUserName);
    if(!pPassword)
    {
        dwError = ERROR_PMD_ACCESS_DENIED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszSalt = pPassword->pw_passwd;
    psPwd = getspnam(pszUserName);
    if (!psPwd && errno == EACCES)
    {
        dwError = ERROR_PMD_ACCESS_DENIED;
        BAIL_ON_PMD_ERROR(dwError);
    }

    /* use the shadow password if it exists. */
    if(psPwd)
    {
        pszSalt = psPwd->sp_pwdp;

        pszEncrypted = crypt(pszPassword, pszSalt);
        if(!pszEncrypted)
        {
            dwError = ERROR_PMD_ACCESS_DENIED;
            BAIL_ON_PMD_ERROR(dwError);
        }

        nValid = (strcmp (pszEncrypted, psPwd->sp_pwdp) == 0);
    }

    *pnValid = nValid;

error:
    if(dwError == ERROR_PMD_ACCESS_DENIED)
    {
        fprintf(stderr,
                "Access denied authenticating : %s",
                pszUserName);
    }
    return dwError;
}

static
uint32_t
count_FQDN_seperator(
    const char* pszFQDN
    )
{
    int  num_dots = 0;
    const char *c = pszFQDN;
    for (; *c != '\0'; c++)
    {
        if (*c == FQDN_SEPARATOR)
        {
            num_dots++;
        }
    }
    return num_dots;
}

uint32_t
FQDN_to_DN(
    const char* pszFQDN,
    char** ppszDN
    )
{
    uint32_t dwError = 0;
    int len = (int)strlen(pszFQDN);
    int iStart = 0;
    int iStop = iStart + 1 ;
    int iDest = 0;
    int i = 0;
    char*       pszDN = NULL;
    uint32_t    dnSize = len + 3 * count_FQDN_seperator(pszFQDN);

    // Allocate memory needed to store DN
    dwError = PMDAllocateMemory(dnSize + 1, (void **)&pszDN);
    BAIL_ON_PMD_ERROR(dwError);

    for ( ; iStop < len; iStop++ )
    {
        if (pszFQDN[iStop] == FQDN_SEPARATOR)
        {
            (pszDN)[iDest++] = 'd';
            (pszDN)[iDest++] = 'c';
            (pszDN)[iDest++] = '=';
            for ( i= iStart; i<iStop; i++)
            {
                (pszDN)[iDest++] = pszFQDN[i];
            }
            (pszDN)[iDest++] = ',';
            iStart = iStop + 1;
            iStop = iStart;
        }
    }
    (pszDN)[iDest++] = 'd';
    (pszDN)[iDest++] = 'c';
    (pszDN)[iDest++] = '=';
    for ( i= iStart; i<iStop; i++)
    {
        (pszDN)[iDest++] = pszFQDN[i];
    }
    *ppszDN = pszDN;

cleanup:
    return dwError;

error:
    PMDFreeMemory(pszDN);
    goto cleanup;
}

static
uint32_t
domain_group_membership_check(
    const char* upn,
    const char* domain_group,
    uint32_t* allowed)
{
    return ERROR_PMD_UNSUPPORTED_PROTOCOL;
}

uint32_t
is_daemon_user(
    uid_t uid,
    gid_t gid,
    int *pnIsDaemonUser
    )
{
    uint32_t dwError = 0;
    int nIsDaemonUser = 0;
    const char *pszDaemonUser = "pmd";
    struct passwd stPwd = {0};
    struct passwd *pResult = NULL;
    int nPwdLength = 0;
    char *pBuffer = NULL;

    if(!pnIsDaemonUser)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nPwdLength = sysconf(_SC_GETPW_R_SIZE_MAX);
    if(nPwdLength <= 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(nPwdLength, (void **)&pBuffer);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = getpwnam_r(pszDaemonUser, &stPwd, pBuffer, nPwdLength, &pResult);
    BAIL_ON_PMD_ERROR(dwError);

    if(!pResult)
    {
        dwError = ERROR_PMD_NO_DAEMON_USER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(uid == stPwd.pw_uid || gid == stPwd.pw_gid)
    {
        nIsDaemonUser = 1;
    }

    *pnIsDaemonUser = nIsDaemonUser;
cleanup:
    PMD_SAFE_FREE_MEMORY(pBuffer);
    return dwError;

error:
    if(pnIsDaemonUser)
    {
        *pnIsDaemonUser = 0;
    }
    goto cleanup;
}

uint32_t
pmd_check_group_membership(
    rpc_binding_handle_t h,
    uint32_t* administrator_access,
    const char* domain_group,
    const char* local_group)
{
    uint32_t dwError = 0;
    unsigned32 prot_seq = 0;
    rpc_transport_info_handle_t info;
    rpc_authz_cred_handle_t hPriv = { 0 };
    unsigned char *authPrinc = NULL;
    unsigned32 group0member = 1;
    unsigned32 dwProtectLevel = 0;
    gid_t gid;
    uid_t uid;

    char* pszDCName = NULL;
    char* pszAccount = NULL;
    char* pszPassword = NULL;
    char* pszDomain = NULL;
    char **ppszMemberships = NULL;
    uint32_t  dwMemberships = 0;
    uint32_t access_allowed;

    gid_t* memberships = NULL;
    uint32_t num_memberships = 0;

    int nBindingHasNoAuth = 0;
    int nIsDaemonUser = 0;

    rpc_binding_inq_prot_seq(h, &prot_seq, &dwError);
    BAIL_ON_PMD_ERROR(dwError);

    rpc_binding_inq_auth_caller(
        h,
        &hPriv,
        &authPrinc,
        &dwProtectLevel,
        NULL, /* unsigned32 *authn_svc, */
        NULL, /* unsigned32 *authz_svc, */
        &dwError);
    if(dwError == RPC_BINDING_HAS_NO_AUTH)
    {
        nBindingHasNoAuth = 1;
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    if (prot_seq == rpc_c_protseq_id_ncalrpc && nBindingHasNoAuth)
    {
        if(IsNullOrEmptyString(local_group))
        {
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_PMD_ERROR(dwError);
        }

        rpc_binding_inq_transport_info(h, &info, &dwError);
        BAIL_ON_PMD_ERROR(dwError);

        //dwError might not indicate failure. check for info
        if(!info)
        {
            dwError = ERROR_PMD_RPC_PEER_NOT_READY;
            BAIL_ON_PMD_ERROR(dwError);
        }

        rpc_lrpc_transport_info_inq_peer_eid(info, &uid, &gid);

        dwError = is_daemon_user(uid, gid, &nIsDaemonUser);
        BAIL_ON_PMD_ERROR(dwError);

        if(nIsDaemonUser)
        {
            dwError = ERROR_PMD_IS_DAEMON_USER_GROUP;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = memberships_from_uid(uid, &memberships, &num_memberships);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = gid_from_group_name(local_group, &gid);
        BAIL_ON_PMD_ERROR(dwError);

        *administrator_access = member_of_groups(gid, memberships, num_memberships);
    }
    else if(!nBindingHasNoAuth)
    {
        if(strchr((const char*)authPrinc, '@'))
        {
            uint32_t allowed;
            if(IsNullOrEmptyString(domain_group))
            {
                dwError = ERROR_PMD_INVALID_PARAMETER;
                BAIL_ON_PMD_ERROR(dwError);
            }
            dwError =  domain_group_membership_check((char*) authPrinc, domain_group,
                   &access_allowed);

            BAIL_ON_PMD_ERROR(dwError);
            *administrator_access = access_allowed;
        }
        else
        {
            if(IsNullOrEmptyString(local_group))
            {
                dwError = ERROR_PMD_INVALID_PARAMETER;
                BAIL_ON_PMD_ERROR(dwError);
            }

            dwError = memberships_from_user_name(
                          (char *)authPrinc,
                          &memberships,
                          &num_memberships);
            BAIL_ON_PMD_ERROR(dwError);

            dwError = gid_from_group_name(local_group, &gid);
            BAIL_ON_PMD_ERROR(dwError);

            *administrator_access = member_of_groups(gid, memberships, num_memberships);
        }
        rpc_string_free(&authPrinc, &dwError);
    }
    else//should not be here.
    {
        fprintf(stderr, "Authorization failed with insufficient data\n");
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    PMDFreeMemory(memberships);
    if(administrator_access && !*administrator_access)
    {
        fprintf(stderr, "Authorization failed for group: %s\n", local_group);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
has_group_access(
    rpc_binding_handle_t hBinding,
    const char* domain_group,
    const char* local_group)
{
    uint32_t dwError = 0;
    uint32_t admin_access = 0;
    if(IsNullOrEmptyString(domain_group) && IsNullOrEmptyString(local_group))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pmd_check_group_membership(
                  hBinding,
                  &admin_access,
                  domain_group,
                  local_group);
    BAIL_ON_PMD_ERROR(dwError);
    if(!admin_access)
    {
        fprintf(stderr,
                "Insufficient group privileges : %s",
                local_group);
        dwError = ERROR_PMD_ACCESS_DENIED;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return dwError;
error:

    goto cleanup;
}

uint32_t
has_admin_access(
    rpc_binding_handle_t hBinding
    )
{
    return has_group_access(hBinding, "Administrators", "root");
}

uint32_t
verify_privsep_daemon(
    rpc_binding_handle_t hBinding
    )
{
    uint32_t dwError = 0;
    unsigned32 prot_seq = 0;
    rpc_transport_info_handle_t info;
    uid_t uid = -1;
    gid_t gid = -1;

    rpc_binding_inq_prot_seq(hBinding, &prot_seq, &dwError);
    BAIL_ON_PMD_ERROR(dwError);
    if (prot_seq == rpc_c_protseq_id_ncalrpc)
    {
        rpc_binding_inq_transport_info(hBinding, &info, &dwError);
        BAIL_ON_PMD_ERROR(dwError);

        //dwError might not indicate failure. check for info
        if(!info)
        {
            dwError = ERROR_PMD_RPC_PEER_NOT_READY;
            BAIL_ON_PMD_ERROR(dwError);
        }

        rpc_lrpc_transport_info_inq_peer_eid(info, &uid, &gid);
        //ensure that the peer is started by root.
        if(uid != 0 && gid != 0)
        {
            dwError = ERROR_PMD_PRIVSEP_INTEGRITY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
error:
    return dwError;
}

uint32_t
has_api_access(
    rpc_binding_handle_t hBinding,
    const char *pszApiName
    )
{
    return 0;
}
