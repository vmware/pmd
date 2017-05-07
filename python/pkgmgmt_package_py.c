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

static char package__doc__[] = "";

static void
package_dealloc(PY_PKG_PACKAGE *self)
{
    Py_XDECREF(self->name);
    Py_XDECREF(self->version);
    Py_XDECREF(self->arch);
    Py_XDECREF(self->reponame);
    Py_XDECREF(self->summary);
    Py_XDECREF(self->description);
    Py_XDECREF(self->sizeFormatted);
    Py_XDECREF(self->release);
    Py_XDECREF(self->license);
    Py_XDECREF(self->url);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
package_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PPY_PKG_PACKAGE self = NULL;

    self = (PPY_PKG_PACKAGE)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        if(!(self->name = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->version = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->arch = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->reponame = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->summary = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->description = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->sizeFormatted = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->release = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->license = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->url = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    return (PyObject *)self;
    
error:
    Py_DECREF(self);
    self = NULL;
    goto cleanup;
}

static int
package_init(
    PY_PKG_PACKAGE *self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    PyObject *name = NULL;
    PyObject *version = NULL;
    PyObject *arch = NULL;
    PyObject *release = NULL;
    PyObject *tmp = NULL;

    static char *kwlist[] = {"name", "version", "arch", "release", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|SSSS", kwlist,
                                      &name, &version, &arch, &release))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (name)
    {
        tmp = self->name;
        Py_INCREF(name);
        self->name = name;
        Py_XDECREF(tmp);
    }
    if (version)
    {
        tmp = self->version;
        Py_INCREF(version);
        self->version = version;
        Py_XDECREF(tmp);
    }
    if (arch)
    {
        tmp = self->arch;
        Py_INCREF(arch);
        self->arch = arch;
        Py_XDECREF(tmp);
    }
    if (release)
    {
        tmp = self->release;
        Py_INCREF(release);
        self->release = release;
        Py_XDECREF(tmp);
    }

cleanup:
    return dwError > 0 ? -1 : 0;

error:
    fprintf(stderr, "Error = %d\n", dwError);
    goto cleanup;
}

uint32_t
py_make_package(
   PTDNF_PKG_INFO pPackage,
   PyObject **ppPyPackage
   )
{
    uint32_t dwError = 0;
    PPY_PKG_PACKAGE pPyPackage = NULL;
    PyTypeObject *retType = &packageType;

    if(!pPackage || !ppPyPackage)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyPackage = (PPY_PKG_PACKAGE)retType->tp_alloc(retType, 0);
    if(!pPyPackage)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyPackage->name = PyBytes_FromString(pPackage->pszName);
    pPyPackage->version = PyBytes_FromString(pPackage->pszVersion ?
                                              pPackage->pszVersion : "");
    pPyPackage->arch = PyBytes_FromString(pPackage->pszArch ?
                                              pPackage->pszArch : "");
    pPyPackage->reponame = PyBytes_FromString(pPackage->pszRepoName ?
                                              pPackage->pszRepoName : "");
    pPyPackage->summary = PyBytes_FromString(pPackage->pszSummary ?
                                              pPackage->pszSummary : "");
    pPyPackage->description = PyBytes_FromString(pPackage->pszDescription ?
                                              pPackage->pszDescription : "");
    pPyPackage->sizeFormatted = PyBytes_FromString(
                                    pPackage->pszFormattedSize ?
                                    pPackage->pszFormattedSize : "");
    pPyPackage->release = PyBytes_FromString(pPackage->pszRelease ?
                                              pPackage->pszRelease : "");
    pPyPackage->license = PyBytes_FromString(pPackage->pszLicense ?
                                              pPackage->pszLicense : "");
    pPyPackage->url = PyBytes_FromString(pPackage->pszURL ?
                                          pPackage->pszURL : "");
    pPyPackage->epoch = pPackage->dwEpoch;
    pPyPackage->size = pPackage->dwInstallSizeBytes;

    *ppPyPackage = (PyObject *)pPyPackage;

cleanup:
    return dwError;

error:
    if(ppPyPackage)
    {
        *ppPyPackage = NULL;
    }
    goto cleanup;
}

static PyGetSetDef package_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef package_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef package_members[] = {
    {"name", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, name), 0,
     "package name"},
    {"version", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, version), 0,
     "package version"},
    {"arch", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, arch), 0,
     "package arch"},
    {"reponame", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, reponame), 0,
     "package reponame"},
    {"summary", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, summary), 0,
     "package summary"},
    {"description", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, description), 0,
     "package description"},
    {"sizeFormatted", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, sizeFormatted), 0,
     "package size formatted in human readable form"},
    {"release", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, release), 0,
     "package release"},
    {"license", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, license), 0,
     "package license"},
    {"url", T_OBJECT_EX, offsetof(PY_PKG_PACKAGE, url), 0,
     "package url"},
    {"epoch", T_INT, offsetof(PY_PKG_PACKAGE, epoch), 0,
     "package epoch"},
    {"size", T_INT, offsetof(PY_PKG_PACKAGE, size), 0,
     "package size in bytes"},
    {NULL}  /* Sentinel */
};

PyTypeObject packageType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "pkg.package",             /*tp_name*/
    sizeof(PY_PKG_PACKAGE),    /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)package_dealloc,/*tp_dealloc*/
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
    package__doc__,            /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    package_methods,           /* tp_methods */
    package_members,           /* tp_members */
    package_getset,            /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)package_init,    /* tp_init */
    0,                         /* tp_alloc */
    package_new,               /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
