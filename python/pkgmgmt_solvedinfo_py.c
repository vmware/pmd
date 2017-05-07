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

static char solvedinfo__doc__[] = "";

static void
solvedinfo_dealloc(PY_PKG_SOLVED_INFO *self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
solvedinfo_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PPY_PKG_SOLVED_INFO self = NULL;

    self = (PPY_PKG_SOLVED_INFO)type->tp_alloc(type, 0);
    if (!self)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return (PyObject *)self;

error:
    if(self)
    {
        Py_DECREF(self);
        self = NULL;
    }
    goto cleanup;
}

static int
solvedinfo_init(
    PY_PKG_SOLVED_INFO *self,
    PyObject *args,
    PyObject *kwds
    )
{
    return 0;
}

uint32_t
py_pkg_names_array(
    PyObject *pyStringList,
    char **ppszString
    )
{
    uint32_t dwError = 0;
    size_t i = 0;
    size_t nCount = 0;
    size_t nLength = 0;
    char *pszString = NULL;

    if(!ppszString)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pyStringList)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nCount = PyList_Size(pyStringList);

    if(nCount == 0)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < nCount; ++i)
    {
        PyObject *pyItem = NULL;
        pyItem = PyList_GetItem(pyStringList, i);
        nLength += pyItem ? PyBytes_Size(pyItem) : 1;
        nLength++;//account for separator
    }

    dwError = PMDAllocateMemory(sizeof(char) * (nLength + 1),
                                (void **)&pszString);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0; i < nCount; ++i)
    {
        PyObject *pyItem = NULL;
        pyItem = PyList_GetItem(pyStringList, i);
        if(i > 0)
        {
            strcat(pszString, ",");
        }
        strcat(pszString,
               pyItem ? PyBytes_AsString(pyItem) : "");
    }

    *ppszString = pszString;

cleanup:
    return dwError;

error:
    if(ppszString)
    {
        *ppszString = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszString);
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
py_pkg_names(
    PyObject *pyPkgList,
    char **ppszPkgNames
    )
{
    uint32_t dwError = 0;
    size_t i = 0;
    size_t nCount = 0;
    size_t nLength = 0;
    char *pszPkgNames = NULL;

    if(!ppszPkgNames)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pyPkgList)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nCount = PyList_Size(pyPkgList);

    if(nCount == 0)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < nCount; ++i)
    {
        PPY_PKG_PACKAGE pyItem = NULL;
        pyItem = (PPY_PKG_PACKAGE)PyList_GetItem(pyPkgList, i);
        nLength += pyItem->name ? PyBytes_Size(pyItem->name) : 1;
        nLength++;//account for separator
    }

    dwError = PMDAllocateMemory(sizeof(char) * (nLength + 1),
                                (void **)&pszPkgNames);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 0; i < nCount; ++i)
    {
        PPY_PKG_PACKAGE pyItem = NULL;
        pyItem = (PPY_PKG_PACKAGE)PyList_GetItem(pyPkgList, i);

        if(i > 0)
        {
            strcat(pszPkgNames, ",");
        }
        strcat(pszPkgNames,
               pyItem->name ? PyBytes_AsString(pyItem->name) : "");
    }

    *ppszPkgNames = pszPkgNames;
cleanup:
    return dwError;

error:
    if(ppszPkgNames)
    {
        *ppszPkgNames = NULL;
    }
    PMD_SAFE_FREE_MEMORY(pszPkgNames);
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

PyObject*
solvedinfo_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_PKG_SOLVED_INFO pSolvedInfo = NULL;
    char *pszRepr = NULL;
    char *pszInstall = NULL;
    char *pszUpgrade = NULL;
    char *pszDowngrade = NULL;
    char *pszRemove = NULL;
    char *pszReinstall = NULL;
    char *pszExisting = NULL;
    char *pszNotResolved = NULL;

    pSolvedInfo = (PPY_PKG_SOLVED_INFO)self;

    dwError = py_pkg_names(pSolvedInfo->pkgsToInstall, &pszInstall);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_pkg_names(pSolvedInfo->pkgsToUpgrade, &pszUpgrade);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_pkg_names(pSolvedInfo->pkgsToDowngrade, &pszDowngrade);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_pkg_names(pSolvedInfo->pkgsToRemove, &pszRemove);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_pkg_names(pSolvedInfo->pkgsToReinstall, &pszReinstall);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_pkg_names(pSolvedInfo->pkgsExisting, &pszExisting);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_pkg_names_array(pSolvedInfo->pkgsNotResolved, &pszNotResolved);

    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "\
{NeedAction: %d,\
 NeedDownload: %d,\
 PkgsToInstall: [%s],\
 PkgsToUpgrade: [%s],\
 PkgsToDowngrade: [%s],\
 PkgsToRemove: [%s],\
 PkgsToReinstall: [%s],\
 PkgsExisting: [%s],\
 PkgsNotResolved: [%s]\
}",
                  pSolvedInfo->needAction,
                  pSolvedInfo->needDownload,
                  pszInstall ? pszInstall : "",
                  pszUpgrade ? pszUpgrade : "",
                  pszDowngrade ? pszDowngrade : "",
                  pszRemove ? pszRemove : "",
                  pszReinstall ? pszReinstall : "",
                  pszExisting ? pszExisting : "",
                  pszNotResolved ? pszNotResolved : ""
                  );
    BAIL_ON_PMD_ERROR(dwError);

    pyRepr = Py_BuildValue("s", pszRepr);
    Py_INCREF(pyRepr);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszInstall);
    PMD_SAFE_FREE_MEMORY(pszUpgrade);
    PMD_SAFE_FREE_MEMORY(pszDowngrade);
    PMD_SAFE_FREE_MEMORY(pszRemove);
    PMD_SAFE_FREE_MEMORY(pszReinstall);
    PMD_SAFE_FREE_MEMORY(pszExisting);
    PMD_SAFE_FREE_MEMORY(pszNotResolved);
    PMD_SAFE_FREE_MEMORY(pszRepr);
    return pyRepr;

error:
    pyRepr = NULL;
    goto cleanup;
}

PyObject*
solvedinfo_str(
    PyObject *self
    )
{
    return solvedinfo_repr(self);
}

uint32_t
py_make_stringlist(
    char **ppszList,
    PyObject **ppyList
    )
{
    uint32_t dwError = 0;
    PyObject *pyList = NULL;

    if(!ppyList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!ppszList)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pyList = PyList_New(0);

    while(ppszList && *ppszList)
    {
        PyObject *pPyString = NULL;

        pPyString = PyBytes_FromString(*ppszList);
        if(PyList_Append(pyList, pPyString) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        ++ppszList;
    }

    *ppyList = pyList;
cleanup:
    return dwError;

error:
    if(ppyList)
    {
        *ppyList = NULL;
    }
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
py_make_pkglist(
    PTDNF_PKG_INFO pPkgList,
    PyObject **ppyList
    )
{
    uint32_t dwError = 0;
    PyObject *pyList = NULL;
    PTDNF_PKG_INFO pInfo = pPkgList;

    if(!ppyList)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!pPkgList)
    {
        dwError = ERROR_PMD_NO_DATA;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pyList = PyList_New(0);

    for(; pInfo; pInfo = pInfo->pNext)
    {
        PyObject *pPyPackage = NULL;

        dwError = py_make_package(pInfo, &pPyPackage);
        BAIL_ON_PMD_ERROR(dwError);

        if(PyList_Append(pyList, pPyPackage) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    *ppyList = pyList;
cleanup:
    return dwError;

error:
    if(ppyList)
    {
        *ppyList = NULL;
    }
    if(dwError == ERROR_PMD_NO_DATA)
    {
        dwError = 0;
    }
    goto cleanup;
}

uint32_t
py_make_solvedinfo(
    PTDNF_SOLVED_PKG_INFO pSolvedInfo,
    PyObject **ppPySolvedInfo
    )
{
    uint32_t dwError = 0;
    PPY_PKG_SOLVED_INFO pPySolvedInfo = NULL;
    PyTypeObject *retType = &solvedInfoType;

    if(!pSolvedInfo || !ppPySolvedInfo)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPySolvedInfo = (PPY_PKG_SOLVED_INFO)retType->tp_alloc(retType, 0);
    if(!pPySolvedInfo)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPySolvedInfo->needAction = pSolvedInfo->nNeedAction;
    pPySolvedInfo->needDownload = pSolvedInfo->nNeedDownload;

    dwError = py_make_pkglist(pSolvedInfo->pPkgsToInstall,
                              &pPySolvedInfo->pkgsToInstall);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_pkglist(pSolvedInfo->pPkgsToUpgrade,
                              &pPySolvedInfo->pkgsToUpgrade);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_pkglist(pSolvedInfo->pPkgsToDowngrade,
                              &pPySolvedInfo->pkgsToDowngrade);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_pkglist(pSolvedInfo->pPkgsToRemove,
                              &pPySolvedInfo->pkgsToRemove);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_pkglist(pSolvedInfo->pPkgsToReinstall,
                              &pPySolvedInfo->pkgsToReinstall);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_pkglist(pSolvedInfo->pPkgsNotAvailable,
                              &pPySolvedInfo->pkgsNotAvailable);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_pkglist(pSolvedInfo->pPkgsExisting,
                              &pPySolvedInfo->pkgsExisting);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_stringlist(pSolvedInfo->ppszPkgsNotResolved,
                                 &pPySolvedInfo->pkgsNotResolved);
    BAIL_ON_PMD_ERROR(dwError);

    *ppPySolvedInfo = (PyObject *)pPySolvedInfo;
cleanup:
    return dwError;

error:
    Py_XDECREF(pPySolvedInfo);
    goto cleanup;
}

static PyGetSetDef solvedinfo_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef solvedinfo_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef solvedinfo_members[] = {
    {"needAction", T_OBJECT_EX, offsetof(PY_PKG_SOLVED_INFO, needAction), 0,
     "does this solution have actionable items?"},
    {"needDownload", T_OBJECT_EX, offsetof(PY_PKG_SOLVED_INFO, needDownload), 0,
     "does this solution need download?"},
    {"pkgsToInstall", T_OBJECT_EX, offsetof(PY_PKG_SOLVED_INFO, pkgsToInstall), 0,
     "list of packages to install"},
    {NULL}  /* Sentinel */
};

PyTypeObject solvedInfoType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "pkg.solvedinfo",                  /*tp_name*/
    sizeof(PY_PKG_SOLVED_INFO),   /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)solvedinfo_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    solvedinfo_repr,             /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    solvedinfo_str,              /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    solvedinfo__doc__,           /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    solvedinfo_methods,          /* tp_methods */
    solvedinfo_members,          /* tp_members */
    solvedinfo_getset,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)solvedinfo_init,   /* tp_init */
    0,                         /* tp_alloc */
    solvedinfo_new,              /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
