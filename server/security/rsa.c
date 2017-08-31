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
rsa_public_encrypt(
    const char *pszData,
    const char *pszPubKeyFile,
    unsigned char **ppszEncrypted,
    int *pnEncryptedLength
    )
{
    uint32_t dwError = 0;
    unsigned char *pszEncrypted = NULL;
    char *pszPubKey = NULL;
    RSA *pRsa = NULL;
    int nEncryptedLength = 0;
    FILE *fp = NULL;

    if(IsNullOrEmptyString(pszData) ||
       IsNullOrEmptyString(pszPubKeyFile) ||
       !ppszEncrypted ||
       !pnEncryptedLength)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fp = fopen(pszPubKeyFile, "r");
    if(!fp)
    {
        dwError = ERROR_PMD_FILE_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRsa = PEM_read_RSA_PUBKEY(fp, &pRsa, NULL, NULL);
    if(!pRsa)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nEncryptedLength = RSA_size(pRsa);
    if(nEncryptedLength <= 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(nEncryptedLength, (void **)&pszEncrypted);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = RSA_public_encrypt(
                  strlen(pszData),
                  (const unsigned char *)pszData,
                  pszEncrypted,
                  pRsa,
                  RSA_PKCS1_PADDING);
    if(dwError == nEncryptedLength)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    *pnEncryptedLength = nEncryptedLength;
    *ppszEncrypted = pszEncrypted;

cleanup:
    if(fp)
    {
        fclose(fp);
    }
    if(pRsa)
    {
        RSA_free(pRsa);
    }
    return dwError;

error:
    goto cleanup;
}

uint32_t
rsa_private_decrypt(
    unsigned char *pszEncrypted,
    int nEncryptedLength,
    const char *pszPrivateKeyFile,
    unsigned char **ppszDecrypted
    )
{
    uint32_t dwError = 0;
    unsigned char *pszDecrypted = NULL;
    RSA *pRsa = NULL;
    int nDecryptedSize = 0;
    int nRsaDecryptSize = 0;
    FILE *fp = NULL;

    if(!pszEncrypted ||
       nEncryptedLength <= 0 ||
       IsNullOrEmptyString(pszPrivateKeyFile) ||
       !ppszDecrypted)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    fp = fopen(pszPrivateKeyFile, "r");
    if(!fp)
    {
        dwError = ERROR_PMD_FILE_NOT_FOUND;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pRsa = PEM_read_RSAPrivateKey(fp, &pRsa, NULL, NULL);
    if(!pRsa)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nDecryptedSize = RSA_size(pRsa);
    if(nDecryptedSize <= 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(nDecryptedSize + 1, (void **)&pszDecrypted);
    BAIL_ON_PMD_ERROR(dwError);

    nRsaDecryptSize = RSA_private_decrypt(
                  nEncryptedLength,
                  pszEncrypted,
                  pszDecrypted,
                  pRsa,
                  RSA_PKCS1_PADDING);
    if(nRsaDecryptSize == -1)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppszDecrypted = pszDecrypted;

cleanup:
    if(fp)
    {
        fclose(fp);
    }
    if(pRsa)
    {
        RSA_free(pRsa);
    }
    return dwError;

error:
    if(ppszDecrypted)
    {
        *ppszDecrypted = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszDecrypted);
    goto cleanup;
}
