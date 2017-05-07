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

static char repodata__doc__[] = "";

static void
repodata_dealloc(PY_PKG_REPODATA *self)
{
    Py_XDECREF(self->id);
    Py_XDECREF(self->name);
    Py_XDECREF(self->baseurl);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
repodata_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PPY_PKG_REPODATA self = NULL;

    self = (PPY_PKG_REPODATA)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        if(!(self->id = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->name = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->baseurl = PyBytes_FromString("")))
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
repodata_init(
    PY_PKG_REPODATA *self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    PyObject *id = NULL;
    PyObject *name = NULL;
    PyObject *baseurl = NULL;
    PyObject *tmp = NULL;

    static char *kwlist[] = {"id", "name", "baseurl", "enabled", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|SSSI", kwlist,
                                      &id, &name, &baseurl, &self->enabled))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (id)
    {
        tmp = self->id;
        Py_INCREF(id);
        self->id = id;
        Py_XDECREF(tmp);
    }
    if (name)
    {
        tmp = self->name;
        Py_INCREF(name);
        self->name = name;
        Py_XDECREF(tmp);
    }
    if (baseurl)
    {
        tmp = self->baseurl;
        Py_INCREF(baseurl);
        self->baseurl = baseurl;
        Py_XDECREF(tmp);
    }

cleanup:
    return dwError > 0 ? -1 : 0;

error:
    fprintf(stderr, "Error = %d\n", dwError);
    goto cleanup;
}

PyObject*
repodata_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_PKG_REPODATA pRepoData = NULL;
    char *pszRepr = NULL;

    pRepoData = (PPY_PKG_REPODATA)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{id: %s, name: %s, baseurl: %s, enabled: %d}",
                  pRepoData->id ? PyBytes_AsString(pRepoData->id) : "",
                  pRepoData->name ? PyBytes_AsString(pRepoData->name) : "",
                  pRepoData->baseurl ? PyBytes_AsString(pRepoData->baseurl) : "",
                  pRepoData->enabled);
    BAIL_ON_PMD_ERROR(dwError);

    pyRepr = Py_BuildValue("s", pszRepr);
    Py_INCREF(pyRepr);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszRepr);
    return pyRepr;

error:
    printf("Error = %d\n", dwError);
    pyRepr = Py_None;
    goto cleanup;

}

PyObject*
repodata_str(
    PyObject *self
    )
{
    return repodata_repr(self);
}

uint32_t
py_make_repodata(
   PTDNF_REPO_DATA pRepoData,
   PyObject **ppPyRepoData
   )
{
    uint32_t dwError = 0;
    PPY_PKG_REPODATA pPyRepoData = NULL;
    PyTypeObject *retType = &repodataType;

    if(!pRepoData || !ppPyRepoData)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRepoData = (PPY_PKG_REPODATA)retType->tp_alloc(retType, 0);
    if(!pPyRepoData)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRepoData->id = PyBytes_FromString(pRepoData->pszId);
    pPyRepoData->name = PyBytes_FromString(pRepoData->pszName);
    pPyRepoData->baseurl = PyBytes_FromString("");
    pPyRepoData->enabled = pRepoData->nEnabled;

    *ppPyRepoData = (PyObject *)pPyRepoData;
cleanup:
    return dwError;

error:
    Py_XDECREF(pPyRepoData);
    goto cleanup;
}

static PyGetSetDef repodata_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef repodata_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef repodata_members[] = {
    {"id", T_OBJECT_EX, offsetof(PY_PKG_REPODATA, id), 0,
     "repo id"},
    {"name", T_OBJECT_EX, offsetof(PY_PKG_REPODATA, name), 0,
     "repo name"},
    {"baseurl", T_OBJECT_EX, offsetof(PY_PKG_REPODATA, baseurl), 0,
     "repo baseurl"},
    {"enabled", T_INT, offsetof(PY_PKG_REPODATA, enabled), 0,
     "repo enabled status"},
    {NULL}  /* Sentinel */
};

PyTypeObject repodataType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "repodata",                  /*tp_name*/
    sizeof(PY_PKG_REPODATA),   /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)repodata_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    repodata_repr,             /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    repodata_str,              /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    repodata__doc__,           /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    repodata_methods,          /* tp_methods */
    repodata_members,          /* tp_members */
    repodata_getset,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)repodata_init,   /* tp_init */
    0,                         /* tp_alloc */
    repodata_new,              /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
