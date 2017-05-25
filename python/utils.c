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

static const char *szLinkStateString[] =
{
    "down",
    "up",
    "unknown"
};

static const char *szLinkModeString[] =
{
    "auto",
    "manual",
    "unknown"
};

const char *
py_link_state_to_string(
    NET_LINK_STATE state
)
{
    if (state > LINK_STATE_UNKNOWN)
    {
        state = LINK_STATE_UNKNOWN;
    }
    return szLinkStateString[state];
}

const char *
py_link_mode_to_string(
    NET_LINK_MODE mode
)
{
    if (mode > LINK_MODE_UNKNOWN)
    {
        mode = LINK_MODE_UNKNOWN;
    }
    return szLinkModeString[mode];

}

uint32_t
py_list_as_string_list(
    PyObject *pyList,
    char ***pppszStrings,
    size_t *pnCount
    )
{
    uint32_t dwError = 0;
    char **ppszStrings = NULL;
    size_t i = 0;
    size_t nCount = 0;

    if(!pyList || !pppszStrings)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    nCount = PyList_Size(pyList);
    if(nCount == 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = PMDAllocateMemory(sizeof(char *) * (nCount + 1),
                                (void **)&ppszStrings);
    BAIL_ON_PMD_ERROR(dwError);
    for(i = 0; i < nCount; ++i)
    {
        PyObject *pyItem = NULL;
        PyObject *pyString = NULL;
        pyItem = PyList_GetItem(pyList, i);
        dwError = py_string_as_string(pyItem, &pyString);
        BAIL_ON_PMD_ERROR(dwError);

        dwError = PMDAllocateString(PyBytes_AsString(pyString),
                                    &ppszStrings[i]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pppszStrings = ppszStrings;
    *pnCount = nCount;

cleanup:
    return dwError;

error:
    if(pppszStrings)
    {
        *pppszStrings = NULL;
    }
    if(pnCount)
    {
        *pnCount = 0;
    }
    PMDFreeStringArray(ppszStrings);
    goto cleanup;
}

uint32_t
py_string_as_string(
    PyObject *pyObj,
    PyObject **ppString
    )
{
    uint32_t dwError = 0;
    PyObject *pString = NULL;
    if(!pyObj || !ppString)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    if(PyBytes_Check(pyObj))
    {
        Py_XINCREF(pyObj);
        pString = pyObj;
    }
    else if(PyUnicode_Check(pyObj))
    {
        pString = PyUnicode_AsUTF8String(pyObj);
    }

    if(!pString)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *ppString = pString;
cleanup:
    return dwError;

error:
    goto cleanup;
}

char *
string_from_py_string(
    PyObject *pyString
    )
{
    char *pszResult = PyBytes_AsString(pyString);
    if(!pszResult || !*pszResult)
    {
        pszResult = NULL;
    }
    return pszResult;
}
