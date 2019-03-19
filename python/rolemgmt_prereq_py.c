/*
 * Copyright © 2019 VMware, Inc.  All Rights Reserved.
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

char rolemgmt_prereq__doc__[] = "";

void
rolemgmt_prereq_dealloc(PY_ROLEMGMT_PREREQ *self)
{
    Py_XDECREF(self->name);
    Py_XDECREF(self->description);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyObject *
rolemgmt_prereq_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PPY_ROLEMGMT_PREREQ self = NULL;

    self = (PPY_ROLEMGMT_PREREQ)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        if(!(self->name = PyBytes_FromString("")))
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
        if(!(self->description = PyBytes_FromString("")))
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

int
rolemgmt_prereq_init(
    PY_ROLEMGMT_PREREQ *self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    PyObject *name = NULL;
    PyObject *description = NULL;
    PyObject *tmp = NULL;

    static char *kwlist[] = {"name", "description", NULL};

    if (!PyArg_ParseTupleAndKeywords(
              args, kwds, "|SS", kwlist,
              &name, &description))
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
    if (description)
    {
        tmp = self->description;
        Py_INCREF(description);
        self->description = description;
        Py_XDECREF(tmp);
    }

cleanup:
    return dwError > 0 ? -1 : 0;

error:
    fprintf(stderr, "Error = %d\n", dwError);
    goto cleanup;
}

PyObject*
rolemgmt_prereq_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_ROLEMGMT_PREREQ pPrereq = NULL;
    char *pszRepr = NULL;

    pPrereq = (PPY_ROLEMGMT_PREREQ)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{name: %s, description: %s}",
                  pPrereq->name ? PyBytes_AsString(pPrereq->name) : "",
                  pPrereq->description ? PyBytes_AsString(pPrereq->description) : "");
    BAIL_ON_PMD_ERROR(dwError);

    pyRepr = Py_BuildValue("s", pszRepr);
    Py_INCREF(pyRepr);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszRepr);
    return pyRepr;

error:
    pyRepr = NULL;
    goto cleanup;
}

PyObject*
rolemgmt_prereq_str(
    PyObject *self
    )
{
    return rolemgmt_prereq_repr(self);
}

uint32_t
rolemgmt_prereq_py_make(
    PPMD_ROLE_PREREQ pPrereq,
    PPY_ROLEMGMT_PREREQ *ppPyPrereq
    )
{
    uint32_t dwError = 0;
    PPY_ROLEMGMT_PREREQ pPyPrereq = NULL;
    PyTypeObject *retType = &rolemgmt_prereqType;

    if(!pPrereq || !ppPyPrereq)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyPrereq = (PPY_ROLEMGMT_PREREQ)retType->tp_alloc(retType, 0);
    if(!pPyPrereq)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyPrereq->name = PyBytes_FromString(pPrereq->pszName);
    pPyPrereq->description = PyBytes_FromString(pPrereq->pszDescription);

    *ppPyPrereq = pPyPrereq;
cleanup:
    return dwError;

error:
    Py_XDECREF(pPyPrereq);
    pPyPrereq = NULL;
    goto cleanup;
}

static PyGetSetDef rolemgmt_prereq_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef rolemgmt_prereq_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef rolemgmt_prereq_members[] = {
    {"name", T_OBJECT_EX, offsetof(PY_ROLEMGMT_PREREQ, name), 0,
     "role name"},
    {"description", T_OBJECT_EX, offsetof(PY_ROLEMGMT_PREREQ, description), 0,
     "role description"},
    {NULL}  /* Sentinel */
};

PyTypeObject rolemgmt_prereqType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "rolemgmt_prereq",            /*tp_name*/
    sizeof(PY_ROLEMGMT_PREREQ),  /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)rolemgmt_prereq_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    rolemgmt_prereq_repr,         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    rolemgmt_prereq_str,          /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    rolemgmt_prereq__doc__,       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    rolemgmt_prereq_methods,      /* tp_methods */
    rolemgmt_prereq_members,      /* tp_members */
    rolemgmt_prereq_getset,       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)rolemgmt_prereq_init,   /* tp_init */
    0,                         /* tp_alloc */
    rolemgmt_prereq_new,          /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
