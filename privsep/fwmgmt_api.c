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
pmd_firewall_get_version(
    char **ppszVersion
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;

    if(!ppszVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString("0.1", &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    *ppszVersion = pszVersion;

cleanup:
    return dwError;

error:
    if(ppszVersion)
    {
        *ppszVersion = NULL;
    }
    goto cleanup;
}

uint32_t
pmd_firewall_get_rules(
    uint32_t nIPV6,
    PPMD_FIREWALL_RULE *ppFirewallRules
    )
{
    uint32_t dwError = 0;
    PIPTABLES_SCRIPT_DATA pData = NULL;
    PPMD_FIREWALL_RULE pFirewallRules = NULL;

    if(!ppFirewallRules)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = read_iptables_script_file(IPTABLES_SCRIPT_PATH, &pData);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_firewall_rules(pData, &pFirewallRules);
    BAIL_ON_PMD_ERROR(dwError);

    *ppFirewallRules = pFirewallRules;

cleanup:
    free_iptables_script_data(pData);
    return dwError;

error:
    if(ppFirewallRules)
    {
        *ppFirewallRules = NULL;
    }
    goto cleanup;
}

//makes some assumptions. pretty soon this function
//will get smart enough to understand options
uint32_t
pmd_firewall_add_rules(
    uint32_t nIPV6,
    uint32_t nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    )
{
    uint32_t dwError = 0;
    char *pszCmd = NULL;

    if(IsNullOrEmptyString(pszChain) || IsNullOrEmptyString(pszRuleSpec))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(
                  &pszCmd,
                  "%s -A %s %s",
                  nIPV6 ? IP6TABLES_CMD : IPTABLES_CMD,
                  pszChain,
                  pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = run_cmd(pszCmd, pszCmd);
    BAIL_ON_PMD_ERROR(dwError);

    if(nPersist)
    {
        dwError = add_firewall_rule_to_script(pszCmd);
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszCmd);
    return dwError;

error:
    goto cleanup;
}

//makes some assumptions. pretty soon this function
//will get smart enough to understand options
uint32_t
pmd_firewall_delete_rules(
    uint32_t nIPV6,
    uint32_t nPersist,
    const char *pszChain,
    const char *pszRuleSpec
    )
{
    uint32_t dwError = 0;
    char *pszCmd = NULL;
    char *pszCmdToDelete = NULL;

    if(IsNullOrEmptyString(pszChain) || IsNullOrEmptyString(pszRuleSpec))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateStringPrintf(
                  &pszCmd,
                  "%s -D %s %s",
                  nIPV6 ? IP6TABLES_CMD : IPTABLES_CMD,
                  pszChain,
                  pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = run_cmd(pszCmd, pszCmd);
    BAIL_ON_PMD_ERROR(dwError);

    if(nPersist)
    {
        dwError = PMDAllocateStringPrintf(
                      &pszCmdToDelete,
                      "%s -A %s %s",
                      nIPV6 ? IP6TABLES_CMD : IPTABLES_CMD,
                      pszChain,
                      pszRuleSpec);
        BAIL_ON_PMD_ERROR(dwError);

        fprintf(stdout, "Deleting firewall rule: %s\n", pszCmdToDelete);

        dwError = delete_firewall_rule_from_script(pszCmdToDelete);
        BAIL_ON_PMD_ERROR(dwError);
    }
cleanup:
    PMD_SAFE_FREE_MEMORY(pszCmd);
    PMD_SAFE_FREE_MEMORY(pszCmdToDelete);
    return dwError;

error:
    goto cleanup;
}

uint32_t
get_current_time(
    char **ppszTime
    )
{
    uint32_t dwError = 0;
    char *pszTime = NULL;
    time_t t = time(NULL);
    struct tm *pTM = NULL;

    if(!ppszTime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pTM = localtime(&t);

    dwError = PMDAllocateMemory(1024, (void **)&pszTime);
    BAIL_ON_PMD_ERROR(dwError);

    strftime(pszTime, 1023, "%a %b %d %H:%M:%S %Y", pTM);

    *ppszTime = pszTime;

cleanup:
    return dwError;

error:
    if(ppszTime)
    {
        *ppszTime = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszTime);
    goto cleanup;
}

uint32_t
write_restore(
    FILE *fp,
    PPMD_FIREWALL_TABLE pTable
    )
{
    uint32_t dwError = 0;
    char *pszRestoreCmd = NULL;
    PPMD_FIREWALL_CMD pCmd = NULL;
    char *pszTime = NULL;

    if(!fp || !pTable)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = get_current_time(&pszTime);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(fp, "# Generated by PMD v1.0 on %s\n", pszTime);
    PMD_SAFE_FREE_MEMORY(pszTime);
    pszTime = NULL;

    fprintf(fp, "*%s\n", pTable->pszName);

    for(pCmd = pTable->pCmds; pCmd; pCmd = pCmd->pNext)
    {
        dwError = get_restore_cmd(pCmd->pszRawCmd, &pszRestoreCmd);
        BAIL_ON_PMD_ERROR(dwError);

        fprintf(fp, "%s\n", pszRestoreCmd);

        PMD_SAFE_FREE_MEMORY(pszRestoreCmd);
        pszRestoreCmd = NULL;
    }

    fprintf(fp, "COMMIT\n");

    dwError = get_current_time(&pszTime);
    BAIL_ON_PMD_ERROR(dwError);

    fprintf(fp, "# Completed on %s\n", pszTime);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszTime);
    PMD_SAFE_FREE_MEMORY(pszRestoreCmd);
    return dwError;

error:
    goto cleanup;
}

uint32_t
pmd_firewall_restore(
    int nIPV6,
    PPMD_FIREWALL_TABLE pTable
    )
{
    uint32_t dwError = 0;
    FILE *fp = NULL;
    int fd = -1;
    PPMD_FIREWALL_TABLE pTemp = NULL;
    char pszLine[1024];
    char *pszRestoreCmd = nIPV6 ? "ip6tables-restore" : "iptables-restore";
    char pszTempFile[] = "/tmp/pmd_firewall.XXXXXX";

    if(!pTable)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fd = mkstemp(pszTempFile);
    if(fd < 1)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    unlink(pszTempFile);//delete on close
    fp = fdopen(fd, "w");
    if(!fp)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pTemp = pTable; pTemp; pTemp = pTemp->pNext)
    {
        dwError = write_restore(fp, pTemp);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = run_cmd_pipe_in(pszRestoreCmd, pszRestoreCmd, fp);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if(fp)
    {
        fclose(fp);
    }
    return dwError;

error:
    goto cleanup;
}
