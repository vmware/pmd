/*
 * Copyright © 2017-2018 VMware, Inc.  All Rights Reserved.
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
print_endpoints(
    rpc_binding_vector_p_t hRpc
    )
{
    unsigned32 i = 0;
    unsigned char *string_binding = NULL;
    unsigned32 sts = 0;

    fprintf (stdout, "Privsep server's communications endpoints are:\n");
    for (i=0; i<hRpc->count; i++)
    {
        rpc_binding_to_string_binding(hRpc->binding_h[i],
                                      &string_binding,
                                      &sts);
        if (string_binding)
        {
            fprintf(stdout, "\t%s\n", (char *) string_binding);
            rpc_string_free(&string_binding, &sts);
        }
    }
}

uint32_t
init_modules(
    )
{
    uint32_t dwError = 0;

    //init tdnf global
    dwError = TDNFInit();
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return dwError;

error:
    goto cleanup;
}

unsigned32
start_ncalrpc_server(
    rpc_binding_vector_p_t *ppBinding
    )
{
    uint32_t dwError = 0;
    rpc_binding_vector_p_t pBinding = NULL;
    struct stEndpoint
    {
        const char* pszProtocol;
        const char* pszEndpoint;
    }
    endpoints[] =
    {
        {"ncalrpc",      PMD_PRIVSEP_NCALRPC_END_POINT},
    };
    rpc_if_handle_t interface_spec[] =
    {
#ifdef DEMO_ENABLED
        demo_privsep_v1_0_s_ifspec,
#endif
        privsepd_v1_0_s_ifspec,
        pkg_privsep_v1_0_s_ifspec
    };
    int nInterfaces = sizeof(interface_spec)/sizeof(*interface_spec);

    if(!ppBinding)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    rpc_server_use_protseq_ep((unsigned char*)endpoints[0].pszProtocol,
                        rpc_c_protseq_max_calls_default,
                        (unsigned char*)endpoints[0].pszEndpoint,
                        &dwError);
    BAIL_ON_PMD_ERROR(dwError);

    rpc_server_inq_bindings(&pBinding, &dwError);
    BAIL_ON_PMD_ERROR(dwError);

    /*
     * Register the Interface with the local endpoint mapper (rpcd)
     */

    printf ("Registering privsep server.... \n");
    while(nInterfaces)
    {
        rpc_server_register_if(interface_spec[--nInterfaces],
                               NULL,
                               NULL,
                               &dwError);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppBinding = pBinding;

cleanup:
    return dwError;

error:
    if(ppBinding)
    {
        *ppBinding = NULL;
    }
    goto cleanup;
}

int main(int argc, char *argv[])
{
    uint32_t dwError = 0;
    rpc_binding_vector_p_t hRpc = NULL;
    setlocale(LC_ALL, "");

    dwError = init_modules();
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateMemory(
                  sizeof(PRIVSEP_SERVER_ENV),
                  (void **)&gpServerEnv);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = start_ncalrpc_server(&hRpc);
    if (dwError)
    {
        fprintf(stderr,
                "start_ncalrpc_server: failed 0x%x : %d\n",
                dwError,
                dwError);
        BAIL_ON_PMD_ERROR(dwError);
    }
    print_endpoints(hRpc);

    /*
     * Begin listening for calls
     */
    DCETHREAD_TRY
    {
        rpc_server_listen(rpc_c_listen_max_calls_default, &dwError);
    }
    DCETHREAD_CATCH_ALL(THIS_CATCH)
    {
        fprintf (stdout, "Server stoppped listening\n");
    }
    DCETHREAD_ENDTRY;

    dwError = pmd_handle_signals();
    BAIL_ON_PMD_ERROR(dwError);

cleanup:

    TDNFUninit();
    free_privsep_server_env(gpServerEnv);

    return dwError;

error:
    dwError = 1;
    goto cleanup;
}
