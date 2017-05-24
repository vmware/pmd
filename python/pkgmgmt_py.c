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

static char pkg__doc__[] = "";

static void
pkg_dealloc(PY_NET *self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
pkg_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PPY_PKG self;

    self = (PPY_PKG)type->tp_alloc(type, 0);
    if (self != NULL)
    {
    }

    return (PyObject *)self;
}

uint32_t
parse_action(
    const char *pszAction,
    TDNF_ALTERTYPE *pnAlterType
    )
{
    uint32_t dwError = 0;
    TDNF_ALTERTYPE nAlterType = -1;

    if(IsNullOrEmptyString(pszAction) || !nAlterType)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(!strcmp(pszAction, "install"))
    {
        nAlterType = ALTER_INSTALL;
    }
    else if(!strcmp(pszAction, "update"))
    {
        nAlterType = ALTER_UPGRADE;
    }
    else if(!strcmp(pszAction, "upgrade"))
    {
        nAlterType = ALTER_UPGRADE;
    }
    else if(!strcmp(pszAction, "downgrade"))
    {
        nAlterType = ALTER_DOWNGRADE;
    }
    else if(!strcmp(pszAction, "erase"))
    {
        nAlterType = ALTER_ERASE;
    }
    else if(!strcmp(pszAction, "reinstall"))
    {
        nAlterType = ALTER_REINSTALL;
    }
    else if(!strcmp(pszAction, "distro-sync"))
    {
        nAlterType = ALTER_DISTRO_SYNC;
    }
    else
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    *pnAlterType = nAlterType;
cleanup:
    return dwError;

error:
    goto cleanup;
}

static void
raise_pkg_exception(
    PPY_PKG self,
    uint32_t dwErrorCode
    )
{
    uint32_t dwError = 0;
    char *pszError = NULL;
    char *pszMessage = NULL;

    //try a package error first but dont fail on it.
    if(self && self->hHandle)
    {
        dwError = pkg_get_error_string(self->hHandle, dwErrorCode, &pszError);
        if(dwError)
        {
            dwError = 0;
        }
    }

    if(IsNullOrEmptyString(pszError))
    {
        dwError = PMDGetErrorString(dwErrorCode, &pszError);
        BAIL_ON_PMD_ERROR(dwError);
    }

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

static int
pkg_init(PY_NET *self, PyObject *args, PyObject *kwds)
{
    PyObject *server = NULL;
    PyObject *tmp = NULL;

    if (! PyArg_ParseTuple(args, "O", &server))
    {
        return -1;
    }

    if (server)
    {
        tmp = self->server;
        Py_INCREF(server);
        self->server= server;
        Py_XDECREF(tmp);
    }

    return 0;
}

static PyObject *
pkg_py_packages(
    PPY_PKG self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PyObject *pyPackageList = Py_None;
    PyObject *pyPkgNameSpecs = NULL;
    PPKGHANDLE hPkgHandle = NULL;
    TDNF_CMD_ARGS stArgs = {0};
    PTDNF_PKG_INFO pPkgInfo = NULL;
    char *ppszCmdsC[] = {"list"};
    char *pszScope = NULL;
    char **ppszPkgNameSpecs = NULL;
    uint32_t i = 0;
    size_t nPkgCount = 0;
    static char *kwlist[] = {"scope", "filter", NULL};

    if (! PyArg_ParseTupleAndKeywords(args,
                                      kwds,
                                      "|sO!",
                                      kwlist,
                                      &pszScope,
                                      &PyList_Type,
                                      &pyPkgNameSpecs))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pyPkgNameSpecs)
    {
        dwError = py_list_as_string_list(pyPkgNameSpecs,
                                         &ppszPkgNameSpecs,
                                         &nPkgCount);
        BAIL_ON_PMD_ERROR(dwError);
    }

    stArgs.nCmdCount = 1;
    stArgs.ppszCmds = ppszCmdsC;

    dwError = pkg_open_handle(self->hHandle, &stArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_list(self->hHandle,
                       hPkgHandle,
                       0,
                       ppszPkgNameSpecs,
                       &pPkgInfo,
                       &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    pyPackageList = PyList_New(0);
    if(!pyPackageList)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < dwCount; ++i)
    {
        PyObject *pPyPackage = NULL;

        dwError = py_make_package(pPkgInfo + i, &pPyPackage);
        BAIL_ON_PMD_ERROR(dwError);

        if(PyList_Append(pyPackageList, pPyPackage) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    PMDFreeStringArrayWithCount(ppszPkgNameSpecs, nPkgCount);
    if(pPkgInfo)
    {
        pkg_free_package_info_array(pPkgInfo, dwCount);
    }
    return pyPackageList;

error:
    pyPackageList = NULL;
    raise_pkg_exception(self, dwError);
    goto cleanup;
}

static PyObject *
pkg_py_repos(
    PPY_PKG self,
    PyObject *arg
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepoList = Py_None;
    PPKGHANDLE hPkgHandle = NULL;
    TDNF_CMD_ARGS stArgs = {0};
    PTDNF_REPO_DATA pRepos = NULL;
    PTDNF_REPO_DATA pReposTemp = NULL;
    char *ppszCmdsC[] = {"repolist"};
    int i = 0;

    stArgs.nCmdCount = 1;
    stArgs.ppszCmds = ppszCmdsC;

    dwError = pkg_open_handle(self->hHandle, &stArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_repolist(self->hHandle,
                           hPkgHandle,
                           0,
                           &pRepos);
    BAIL_ON_PMD_ERROR(dwError);

    pyRepoList = PyList_New(0);
    if(!pyRepoList)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(pReposTemp = pRepos; pReposTemp; pReposTemp = pReposTemp->pNext)
    {
        PyObject *pPyRepoData = NULL;

        dwError = py_make_repodata(pReposTemp, &pPyRepoData);
        BAIL_ON_PMD_ERROR(dwError);

        if(PyList_Append(pyRepoList, pPyRepoData) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    pkg_free_repos(pRepos);
    return pyRepoList;

error:
    pyRepoList = NULL;
    raise_pkg_exception(self, dwError);
    goto cleanup;
}

static PyObject *
pkg_py_count(
    PPY_PKG self,
    PyObject *arg
    )
{
    uint32_t dwError = 0;
    uint32_t dwCount = 0;
    PyObject *pyCount = Py_None;
    PPKGHANDLE hPkgHandle = NULL;
    TDNF_CMD_ARGS stArgs = {0};
    char *ppszCmdsC[] = {"count"};
    stArgs.nCmdCount = 1;
    stArgs.ppszCmds = ppszCmdsC;

    dwError = pkg_open_handle(self->hHandle, &stArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_count(self->hHandle, hPkgHandle, &dwCount);
    BAIL_ON_PMD_ERROR(dwError);

    pyCount = Py_BuildValue("I", dwCount);

cleanup:
    return pyCount;

error:
    pyCount = NULL;
    raise_pkg_exception(self, dwError);
    goto cleanup;
}

static PyObject *
pkg_py_getversion(
    PPY_PKG self,
    void *closure)
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    PyObject *pyVersion = Py_None;

    dwError = pkg_version(self->hHandle, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    pyVersion = PyBytes_FromString(pszVersion);
    if(!pyVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    PMD_SAFE_FREE_MEMORY(pszVersion);
    return pyVersion;
error:
    pyVersion = NULL;
    raise_pkg_exception(self, dwError);
    goto cleanup;
}

static PyObject *
pkg_py_alter(
    TDNF_ALTERTYPE alterType,
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PyObject *pyPkgList = NULL;
    PyObject *ppyResult = Py_None;
    char **ppszPackages = NULL;
    static char *kwlist[] = {"packages", NULL};
    PPKGHANDLE hPkgHandle = NULL;
    TDNF_CMD_ARGS stArgs = {0};
    char *pszCmd = NULL;
    size_t nPkgCount = 0;
    int i = 0;
    TDNF_ALTERTYPE alterTypeToUse = alterType;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;

    if (! PyArg_ParseTupleAndKeywords(args,
                                      kwds,
                                      "|O!",
                                      kwlist,
                                      &PyList_Type,
                                      &pyPkgList))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(pyPkgList)
    {
        dwError = py_list_as_string_list(pyPkgList, &ppszPackages, &nPkgCount);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_translate_alter_cmd(nPkgCount, alterType, &alterTypeToUse);
    BAIL_ON_PMD_ERROR(dwError);

    stArgs.nCmdCount = nPkgCount + 1;
    dwError = PMDAllocateMemory(sizeof(char *) * stArgs.nCmdCount,
                                (void **)&stArgs.ppszCmds);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_get_cmd_string(alterType, &pszCmd);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszCmd, &stArgs.ppszCmds[0]);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 1; i < stArgs.nCmdCount; ++i)
    {
        dwError = PMDAllocateString(ppszPackages[i-1], &stArgs.ppszCmds[i]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_open_handle(self->hHandle, &stArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_resolve(self->hHandle, hPkgHandle, alterTypeToUse, &pSolvedInfo);
printf("dwError = %d\n", dwError);
    BAIL_ON_PMD_ERROR(dwError);

printf("need = %d\n", pSolvedInfo->nNeedAction);
    if(pSolvedInfo->nNeedAction)
    {
        dwError = pkg_alter(self->hHandle, hPkgHandle, alterTypeToUse, NULL);
        BAIL_ON_PMD_ERROR(dwError);
    }

    ppyResult = Py_None;

cleanup:
    pkg_free_solvedinfo(pSolvedInfo);
    PMD_SAFE_FREE_MEMORY(pszCmd);
    PMDFreeStringArray(ppszPackages);
    PMDFreeStringArrayWithCount(stArgs.ppszCmds, stArgs.nCmdCount);
    return ppyResult;

error:
    if(ppyResult)
    {
        Py_XDECREF(ppyResult);
    }
    ppyResult = NULL;
    raise_pkg_exception(self, dwError);
    goto cleanup;
}

static PyObject *
pkg_py_install(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    return pkg_py_alter(ALTER_INSTALL, self, args, kwds);
}

static PyObject *
pkg_py_erase(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    return pkg_py_alter(ALTER_ERASE, self, args, kwds);
}

static PyObject *
pkg_py_update(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    return pkg_py_alter(ALTER_UPGRADE, self, args, kwds);
}

static PyObject *
pkg_py_downgrade(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    return pkg_py_alter(ALTER_DOWNGRADE, self, args, kwds);
}

static PyObject *
pkg_py_distro_sync(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    return pkg_py_alter(ALTER_DISTRO_SYNC, self, args, kwds);
}

static PyObject *
pkg_py_reinstall(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    return pkg_py_alter(ALTER_REINSTALL, self, args, kwds);
}

static PyObject *
pkg_py_resolve(
    PY_PKG *self,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    const char *pszAction = NULL;
    PyObject *pyPkgList = NULL;
    PyObject *ppyResult = Py_None;
    char **ppszPackages = NULL;
    static char *kwlist[] = {"action", "packages", NULL};
    size_t nPkgCount = 0;
    PPKGHANDLE hPkgHandle = NULL;
    TDNF_CMD_ARGS stArgs = {0};
    char *pszCmd = NULL;
    int i = 0;
    PTDNF_SOLVED_PKG_INFO pSolvedInfo = NULL;
    TDNF_ALTERTYPE nAlterType = -1;

    if (! PyArg_ParseTupleAndKeywords(args,
                                      kwds,
                                      "s|O!",
                                      kwlist,
                                      &pszAction,
                                      &PyList_Type,
                                      &pyPkgList))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (IsNullOrEmptyString(pszAction))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = parse_action(pszAction, &nAlterType);

    if(pyPkgList)
    {
        dwError = py_list_as_string_list(pyPkgList, &ppszPackages, &nPkgCount);
        BAIL_ON_PMD_ERROR(dwError);
    }

    stArgs.nCmdCount = nPkgCount + 1;
    dwError = PMDAllocateMemory(sizeof(char *) * stArgs.nCmdCount,
                                (void **)&stArgs.ppszCmds);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = PMDAllocateString(pszAction, &stArgs.ppszCmds[0]);
    BAIL_ON_PMD_ERROR(dwError);

    for(i = 1; i < stArgs.nCmdCount; ++i)
    {
        dwError = PMDAllocateString(ppszPackages[i-1], &stArgs.ppszCmds[i]);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = pkg_open_handle(self->hHandle, &stArgs, &hPkgHandle);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = pkg_resolve(self->hHandle, hPkgHandle, nAlterType, &pSolvedInfo);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = py_make_solvedinfo(pSolvedInfo, &ppyResult);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pkg_free_solvedinfo(pSolvedInfo);
    PMDFreeStringArray(ppszPackages);
    return ppyResult;

error:
    if(ppyResult)
    {
        Py_XDECREF(ppyResult);
    }
    ppyResult = NULL;
    raise_pkg_exception(self, dwError);
    goto cleanup;
}


static PyGetSetDef pkg_getset[] = {
    {"version",
     (getter)pkg_py_getversion, (setter)NULL,
     "get pkgmgmt version",
     NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef pkg_methods[] =
{
    {"count", (PyCFunction)pkg_py_count, METH_NOARGS,
     "pkg.count() \n\
     return count of all known packages. installed and available.\n"},
    {"repos", (PyCFunction)pkg_py_repos, METH_NOARGS,
     "pkg.repos() \n\
     return list of all available repositories both enabled and disabled.\n"},
    {"packages", (PyCFunction)pkg_py_packages, METH_VARARGS|METH_KEYWORDS,
     "pkg.packages(filter) \n\
     filter: string array of package names. Optional.\n\
     return list of packages in all enabled repositories.\n"},
    {"install", (PyCFunction)pkg_py_install, METH_VARARGS|METH_KEYWORDS,
     "pkg.install(packages) \n\
     packages: string array of package names to install.\n\
     install specified package or packages.\n"},
    {"erase", (PyCFunction)pkg_py_erase, METH_VARARGS|METH_KEYWORDS,
     "pkg.erase(packages) \n\
     packages: string array of package names to erase.\n\
     erase specified package or packages.\n"},
    {"update", (PyCFunction)pkg_py_update, METH_VARARGS|METH_KEYWORDS,
     "pkg.update(packages) \n\
     packages: string array of package names to update.\n\
     update specified package or packages or update all available if called with no args.\n"},
    {"downgrade", (PyCFunction)pkg_py_downgrade, METH_VARARGS|METH_KEYWORDS,
     "pkg.downgrade(packages) \n\
     packages: string array of package names to downgrade.\n\
     downgrade specified package or packages or downgrade all available if called with no args.\n"},
    {"distro_sync", (PyCFunction)pkg_py_distro_sync, METH_VARARGS|METH_KEYWORDS,
     "pkg.distro_sync(packages) \n\
     distro_sync specified package or packages or distro_sync all installed if called with no args.\n"},
    {"reinstall", (PyCFunction)pkg_py_reinstall, METH_VARARGS|METH_KEYWORDS,
     "pkg.reinstall(packages) \n\
     packages: string array of package names to reinstall.\n\
     reinstall specified package or packages.\n"},
    {"resolve", (PyCFunction)pkg_py_resolve, METH_VARARGS|METH_KEYWORDS,
     "pkg.resolve(action=install, packages=['pkg1', 'pkg2']) \n\
     solve for install/update/erase of package or packages. return a solve object which has information on packages affected.\n"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef pkg_members[] =
{
    {"server", T_OBJECT_EX, offsetof(PY_NET, server), 0,
     "server details"},
    {NULL}  /* Sentinel */
};


PyTypeObject pkgType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "server.pkg",              /*tp_name*/
    sizeof(PY_PKG),            /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)pkg_dealloc,   /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    pkg__doc__,                /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    pkg_methods,               /* tp_methods */
    pkg_members,               /* tp_members */
    pkg_getset,                /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)pkg_init,        /* tp_init */
    0,                         /* tp_alloc */
    pkg_new,                   /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
