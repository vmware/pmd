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

static char system__doc__[] = "";

static void
system_dealloc(PY_SYSTEM *self)
{
    Py_XDECREF(self->pDuid);
    Py_XDECREF(self->pDnsMode);
    Py_XDECREF(self->pServersList);
    Py_XDECREF(self->pDomainsList);
    Py_XDECREF(self->pNtpServersList);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
system_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PPY_SYSTEM self;

    self = (PPY_SYSTEM)type->tp_alloc(type, 0);
    if (self != NULL)
    {
    }

    return (PyObject *)self;
}

static int
system_init(PY_SYSTEM *self, PyObject *args, PyObject *kwds)
{
    PyObject *server = NULL;

    if (! PyArg_ParseTuple(args, "O", &server))
    {
        return -1;
    }

    return 0;
}


PyObject*
system_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_SYSTEM pSystem = NULL;
    char *pszRepr = NULL;

    pSystem = (PPY_SYSTEM)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{DUID: %s, DNS Mode: %s, DNS ServerList: %s, "
                  "DNS DomainList: %s, NTP ServerList: %s}",
                  (pSystem->pDuid != Py_None) ?
                  PyBytes_AsString(pSystem->pDuid) : "",
                  (pSystem->pDnsMode != Py_None) ?
                  PyBytes_AsString(pSystem->pDnsMode) : "",
                  (pSystem->pServersList != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pSystem->pServersList)) : "",
                  (pSystem->pDomainsList != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pSystem->pDomainsList)) : "",
                  (pSystem->pNtpServersList!= Py_None) ?
                  PyBytes_AsString(PyObject_Str(pSystem->pNtpServersList)) :
                  "");
    BAIL_ON_PMD_ERROR(dwError);

    pyRepr = Py_BuildValue("s", pszRepr);
    Py_INCREF(pyRepr);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszRepr);
    return pyRepr;

error:
    pyRepr = Py_None;
    goto cleanup;
}

PyObject*
system_str(
    PyObject *self
    )
{
    return system_repr(self);
}

static PyGetSetDef system_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef system_methods[] =
{
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef system_members[] =
{
    {"duid", T_OBJECT_EX, offsetof(PY_SYSTEM, pDuid), 0,
     "duid of the system"},
    {"dns_mode", T_OBJECT_EX, offsetof(PY_SYSTEM, pDnsMode), 0,
     "mode of dns"},
    {"dns_servers", T_OBJECT_EX, offsetof(PY_SYSTEM, pServersList), 0,
     "dns servers list of the system"},
    {"dns_domains", T_OBJECT_EX, offsetof(PY_SYSTEM, pDomainsList), 0,
     "dns domains of the system"},
    {"ntp_servers", T_OBJECT_EX, offsetof(PY_SYSTEM, pNtpServersList), 0,
     "ntp servers of the system"},
    {NULL}  /* Sentinel */
};

PyTypeObject systemType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "net.system",              /*tp_name*/
    sizeof(PY_SYSTEM),         /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)system_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    system_repr,               /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    system_str,                /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    system__doc__,             /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    system_methods,            /* tp_methods */
    system_members,            /* tp_members */
    system_getset,             /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)system_init,     /* tp_init */
    0,                         /* tp_alloc */
    system_new,                /* tp_new */
    0,                         /* tp_free */
    0                          /* tp_is_gc */
};
