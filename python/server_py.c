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

static char server__doc__[] = "";

static void
server_dealloc(PY_PMD_SERVER *self)
{
    Py_XDECREF(self->name);
    Py_XDECREF(self->user);
    Py_XDECREF(self->pass);
    Py_XDECREF(self->domain);
    Py_XDECREF(self->spn);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
server_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PPY_PMD_SERVER self;

    self = (PPY_PMD_SERVER)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        self->name = PyBytes_FromString("");
        if (self->name == NULL)
        {
            Py_DECREF(self);
            return NULL;
        }
        self->user = PyBytes_FromString("");
        if (self->user == NULL)
        {
            Py_DECREF(self);
            return NULL;
        }
        self->pass = PyBytes_FromString("");
        if (self->pass == NULL)
        {
            Py_DECREF(self);
            return NULL;
        }
        self->domain = PyBytes_FromString("");
        if (self->domain == NULL)
        {
            Py_DECREF(self);
            return NULL;
        }
        self->spn = PyBytes_FromString("");
        if (self->spn == NULL)
        {
            Py_DECREF(self);
            return NULL;
        }
    }

    return (PyObject *)self;
}

static int
server_init(PY_PMD_SERVER *self, PyObject *args, PyObject *kwds)
{
    uint32_t dwError = 0;
    PyObject *name = NULL;
    PyObject *user = NULL;
    PyObject *pass = NULL;
    PyObject *domain = NULL;
    PyObject *spn = NULL;

    static char *kwlist[] = {"name", "user", "pwd", "domain", "spn", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "|OOOOO", kwlist,
                                      &name, &user, &pass, &domain, &spn))
    {
        return -1;
    }

    if (name)
    {
        dwError = py_string_as_string(name, &self->name);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (user)
    {
        dwError = py_string_as_string(user, &self->user);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (pass)
    {
        dwError = py_string_as_string(pass, &self->pass);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (domain)
    {
        dwError = py_string_as_string(domain, &self->domain);
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (spn)
    {
        dwError = py_string_as_string(spn, &self->spn);
        BAIL_ON_PMD_ERROR(dwError);
    }

error:
    return dwError;
}

static PyObject *
server_get_firewall(
    PPY_PMD_SERVER self,
    void *closure)
{
    uint32_t dwError = 0;
    PPMDHANDLE hHandle = NULL;
    PPY_FIREWALL pFirewall = NULL;
    PyObject *pyFirewall = NULL;
    PyTypeObject *retType = &firewallType;

    dwError = rpc_open("fwmgmt",
                       string_from_py_string(self->name),
                       string_from_py_string(self->user),
                       string_from_py_string(self->domain),
                       string_from_py_string(self->pass),
                       string_from_py_string(self->spn),
                       &hHandle);
    if(dwError > 0)
    {
        goto error;
    }

    pFirewall = (PPY_FIREWALL)retType->tp_alloc(retType, 0);
    pFirewall->hHandle = hHandle;
    pFirewall->server = (PyObject *)self;

    pyFirewall = (PyObject *)pFirewall;

cleanup:
    return pyFirewall;
error:
    pyFirewall = Py_None;
    goto cleanup;
}

static PyObject *
server_getnet(
    PPY_PMD_SERVER self,
    void *closure)
{
    uint32_t dwError = 0;
    PPMDHANDLE hHandle = NULL;
    PPY_NET pNet = NULL;
    PyObject *pyNet = NULL;
    PyTypeObject *retType = &netType;

    dwError = rpc_open("net",
                       string_from_py_string(self->name),
                       string_from_py_string(self->user),
                       string_from_py_string(self->domain),
                       string_from_py_string(self->pass),
                       string_from_py_string(self->spn),
                       &hHandle);
    if(dwError > 0)
    {
        goto error;
    }

    pNet = (PPY_NET)retType->tp_alloc(retType, 0);
    pNet->hHandle = hHandle;
    pNet->server = (PyObject *)self;

    pyNet = (PyObject *)pNet;

cleanup:
    return pyNet;
error:
    pyNet = Py_None;
    goto cleanup;
}

static PyObject *
server_getpkg(
    PPY_PMD_SERVER self,
    void *closure)
{
    uint32_t dwError = 0;
    PPMDHANDLE hHandle = NULL;
    PPY_PKG pPkg = NULL;
    PyObject *pyPkg = NULL;
    PyTypeObject *retType = &pkgType;

    dwError = rpc_open("pkg",
                       string_from_py_string(self->name),
                       string_from_py_string(self->user),
                       string_from_py_string(self->domain),
                       string_from_py_string(self->pass),
                       string_from_py_string(self->spn),
                       &hHandle);
    if(dwError > 0)
    {
        goto error;
    }

    pPkg = (PPY_PKG)retType->tp_alloc(retType, 0);
    pPkg->hHandle = hHandle;
    pPkg->server = (PyObject *)self;

    pyPkg = (PyObject *)pPkg;

cleanup:
    return pyPkg;
error:
    pyPkg = Py_None;
    goto cleanup;
}

static PyObject *
server_get_rolemgmt(
    PPY_PMD_SERVER self,
    void *closure)
{
    uint32_t dwError = 0;
    PPMDHANDLE hHandle = NULL;
    PPY_ROLEMGMT pRolemgmt = NULL;
    PyObject *pyRolemgmt = NULL;
    PyTypeObject *retType = &rolemgmtType;

    dwError = rpc_open("rolemgmt",
                       string_from_py_string(self->name),
                       string_from_py_string(self->user),
                       string_from_py_string(self->domain),
                       string_from_py_string(self->pass),
                       string_from_py_string(self->spn),
                       &hHandle);
    if(dwError > 0)
    {
        goto error;
    }

    pRolemgmt = (PPY_ROLEMGMT)retType->tp_alloc(retType, 0);
    pRolemgmt->hHandle = hHandle;
    pRolemgmt->server = (PyObject *)self;

    pyRolemgmt = (PyObject *)pRolemgmt;

cleanup:
    return pyRolemgmt;
error:
    pyRolemgmt = Py_None;
    goto cleanup;
}

static PyGetSetDef server_getset[] = {
    {"firewall",
     (getter)server_get_firewall, (setter)NULL,
     "firewall interface",
     NULL},
    {"net",
     (getter)server_getnet, (setter)NULL,
     "netmgmt interface",
     NULL},
    {"pkg",
     (getter)server_getpkg, (setter)NULL,
     "pkgmgmt interface",
     NULL},
    {"rolemgmt",
     (getter)server_get_rolemgmt, (setter)NULL,
     "pkgmgmt interface",
     NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef server_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef server_members[] = {
    {"name", T_OBJECT_EX, offsetof(PY_PMD_SERVER, name), 0,
     "server name"},
    {"user", T_OBJECT_EX, offsetof(PY_PMD_SERVER, user), 0,
     "user name"},
    {"pwd", T_OBJECT_EX, offsetof(PY_PMD_SERVER, pass), 0,
     "user name"},
    {"domain", T_OBJECT_EX, offsetof(PY_PMD_SERVER, domain), 0,
     "domain name"},
    {"spn", T_OBJECT_EX, offsetof(PY_PMD_SERVER, spn), 0,
     "service principal name"},
    {NULL}  /* Sentinel */
};

PyTypeObject serverType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "pmd.server",              /*tp_name*/
    sizeof(PY_PMD_SERVER),     /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)server_dealloc,/*tp_dealloc*/
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
    server__doc__,             /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    server_methods,            /* tp_methods */
    server_members,            /* tp_members */
    server_getset,             /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)server_init,     /* tp_init */
    0,                         /* tp_alloc */
    server_new,                /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};

