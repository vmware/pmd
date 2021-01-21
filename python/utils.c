/*
 * Copyright © 2016-2019 VMware, Inc.  All Rights Reserved.
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

#define ELEMENTSOF(x) (sizeof(x)/sizeof((x)[0]))

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

static const char *const net_dhcp_modes[_DHCP_MODE_MAX] = {
    [DHCP_MODE_NO]   = "no",
    [DHCP_MODE_YES]  = "yes",
    [DHCP_MODE_IPV4] = "ipv4",
    [DHCP_MODE_IPV6] = "ipv6",
};

const char *
py_net_dhcp_modes_to_name(
    int id
    )
{
    if (id < 0)
    {
        return "n/a";
    }
    if ((size_t) id >= ELEMENTSOF(net_dhcp_modes))
    {
        return NULL;
    }
    return net_dhcp_modes[id];
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
py_object_as_py_list(
    PyObject *pyObj,
    PyObject **pyList
    )
{
    uint32_t dwError = 0;
    PyObject *pList = NULL;
    PyObject *iter = NULL;
    PyObject *next = NULL;

    if (!pyObj || !pyList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    iter = PyObject_GetIter(pyObj);
    if (!iter) {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    pList = PyList_New(0);
    if (!pList)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }
    next = PyIter_Next(iter);
    while (next)
    {
        if (PyList_Append(pList, next) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        Py_DECREF(next);
        next = PyIter_Next(iter);
    }

    *pyList = pList;
cleanup:
    return dwError;

error:
    if (pList)
    {
        Py_DECREF(pList);
    }
    if (pyList)
    {
        *pyList = NULL;
    }
    goto cleanup;
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

void
raise_exception(
    uint32_t dwErrorCode
    )
{
    uint32_t dwError = 0;
    char *pszError = NULL;
    char *pszMessage = NULL;

    dwError = PMDGetErrorString(dwErrorCode, &pszError);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateStringPrintf(&pszMessage,
                                      "Error = %d: %s",
                                      dwErrorCode,
                                      pszError);
    BAIL_ON_PMD_ERROR(dwError);

    PyErr_SetString(PyExc_Exception, pszMessage);

cleanup:

    PMD_SAFE_FREE_MEMORY(pszMessage);
    PMD_SAFE_FREE_MEMORY(pszError);
    return;
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
