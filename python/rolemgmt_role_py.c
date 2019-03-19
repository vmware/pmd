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

char rolemgmt_role__doc__[] = "";

void
rolemgmt_role_dealloc(PY_ROLEMGMT_ROLE *self)
{
    Py_XDECREF(self->id);
    Py_XDECREF(self->name);
    Py_XDECREF(self->displayname);
    Py_XDECREF(self->description);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyObject *
rolemgmt_role_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PPY_ROLEMGMT_ROLE self = NULL;

    self = (PPY_ROLEMGMT_ROLE)type->tp_alloc(type, 0);
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
        if(!(self->displayname= PyBytes_FromString("")))
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
rolemgmt_role_init(
    PY_ROLEMGMT_ROLE *self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    PyObject *id = NULL;
    PyObject *name = NULL;
    PyObject *displayname = NULL;
    PyObject *description = NULL;
    PyObject *tmp = NULL;

    static char *kwlist[] = {"id", "name", "displayname", "description", NULL};

    if (!PyArg_ParseTupleAndKeywords(
              args, kwds, "|SSSS", kwlist,
              &id, &name, &displayname, &description))
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
    if (displayname)
    {
        tmp = self->displayname;
        Py_INCREF(displayname);
        self->displayname = displayname;
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
rolemgmt_role_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_ROLEMGMT_ROLE pRole = NULL;
    char *pszRepr = NULL;

    pRole = (PPY_ROLEMGMT_ROLE)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{id: %s, name: %s, displayname: %s, description: %s}",
                  pRole->id ? PyBytes_AsString(pRole->id) : "",
                  pRole->name ? PyBytes_AsString(pRole->name) : "",
                  pRole->displayname ? PyBytes_AsString(pRole->displayname) : "",
                  pRole->description ? PyBytes_AsString(pRole->description) : "");
    BAIL_ON_PMD_ERROR(dwError);

    pyRepr = Py_BuildValue("s", pszRepr);
    Py_INCREF(pyRepr);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszRepr);
    return pyRepr;

error:
    pyRepr = NULL;
    raise_exception(dwError);
    goto cleanup;
}

PyObject*
rolemgmt_role_str(
    PyObject *self
    )
{
    return rolemgmt_role_repr(self);
}

uint32_t
rolemgmt_role_py_make(
    PPMD_ROLEMGMT_ROLE pRole,
    PyObject **ppPyRole
    )
{
    uint32_t dwError = 0;
    PPY_ROLEMGMT_ROLE pPyRole = NULL;
    PyTypeObject *retType = &rolemgmt_roleType;

    if(!pRole || !ppPyRole)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRole = (PPY_ROLEMGMT_ROLE)retType->tp_alloc(retType, 0);
    if(!pPyRole)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRole->id = PyBytes_FromString(pRole->pszId);
    pPyRole->name = PyBytes_FromString(pRole->pszName);
    pPyRole->displayname = PyBytes_FromString(pRole->pszDisplayName ? pRole->pszDisplayName : "");
    pPyRole->description = PyBytes_FromString(pRole->pszDescription);

    *ppPyRole = (PyObject *)pPyRole;
cleanup:
    return dwError;

error:
    Py_XDECREF(pPyRole);
    pPyRole = NULL;
    raise_exception(dwError);
    goto cleanup;
}

static PyGetSetDef rolemgmt_role_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef rolemgmt_role_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef rolemgmt_role_members[] = {
    {"id", T_OBJECT_EX, offsetof(PY_ROLEMGMT_ROLE, id), 0,
     "role id"},
    {"name", T_OBJECT_EX, offsetof(PY_ROLEMGMT_ROLE, name), 0,
     "role name"},
    {"displayname", T_OBJECT_EX, offsetof(PY_ROLEMGMT_ROLE, displayname), 0,
     "role display name"},
    {"description", T_OBJECT_EX, offsetof(PY_ROLEMGMT_ROLE, description), 0,
     "role description"},
    {NULL}  /* Sentinel */
};

PyTypeObject rolemgmt_roleType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "rolemgmt_role",            /*tp_name*/
    sizeof(PY_ROLEMGMT_ROLE),  /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)rolemgmt_role_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    rolemgmt_role_repr,         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    rolemgmt_role_str,          /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    rolemgmt_role__doc__,       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    rolemgmt_role_methods,      /* tp_methods */
    rolemgmt_role_members,      /* tp_members */
    rolemgmt_role_getset,       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)rolemgmt_role_init,   /* tp_init */
    0,                         /* tp_alloc */
    rolemgmt_role_new,          /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
