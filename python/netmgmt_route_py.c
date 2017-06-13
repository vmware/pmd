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

static char route__doc__[] = "";

static void
route_dealloc(PY_IP_ROUTE *self)
{
    Py_XDECREF(self->pRouteDestNetwork);
    Py_XDECREF(self->pRouteSourceNetwork);
    Py_XDECREF(self->pRouteGateway);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
route_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PPY_IP_ROUTE self;

    self = (PPY_IP_ROUTE)type->tp_alloc(type, 0);
    if (self != NULL)
    {
    }

    return (PyObject *)self;
}

static int
route_init(PY_IP_ROUTE *self, PyObject *args, PyObject *kwds)
{
    PyObject *server = NULL;

    if (! PyArg_ParseTuple(args, "O", &server))
    {
        return -1;
    }

    return 0;
}


PyObject*
route_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_IP_ROUTE pRoute = NULL;
    char *pszRepr = NULL;

    pRoute = (PPY_IP_ROUTE)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{destination network: %s, source network: %s, gateway: %s "
                  "scope: %d, metric: %d, table: %d}",
                  (pRoute->pRouteDestNetwork != Py_None) ?
                  PyBytes_AsString(pRoute->pRouteDestNetwork) : "",
                  (pRoute->pRouteSourceNetwork != Py_None) ?
                  PyBytes_AsString(pRoute->pRouteSourceNetwork) : "",
                  (pRoute->pRouteGateway != Py_None) ?
                  PyBytes_AsString(pRoute->pRouteGateway) : "",
                  pRoute->scope, pRoute->metric, pRoute->table);
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
route_str(
    PyObject *self
    )
{
    return route_repr(self);
}

static PyGetSetDef route_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef route_methods[] =
{
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef route_members[] =
{
    {"destination_network", T_OBJECT_EX, offsetof(PY_IP_ROUTE, pRouteDestNetwork), 0,
     "destination network of the route"},
    {"source_network", T_OBJECT_EX, offsetof(PY_IP_ROUTE, pRouteSourceNetwork), 0,
     "source network of the route"},
    {"gateway", T_OBJECT_EX, offsetof(PY_IP_ROUTE, pRouteGateway), 0,
     "gateway of the route"},
    {"scope", T_INT, offsetof(PY_IP_ROUTE, scope), 0,
     "scope of the route"},
    {"metric", T_INT, offsetof(PY_IP_ROUTE, metric), 0,
     "metric of the route"},
    {"table", T_INT, offsetof(PY_IP_ROUTE, table), 0,
     "table identifier for the route"},
    {NULL}  /* Sentinel */
};

PyTypeObject routeType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "net.link.route",          /*tp_name*/
    sizeof(PY_IP_ROUTE),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)route_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    route_repr,                /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    route_str,                 /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    route__doc__,              /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    route_methods,             /* tp_methods */
    route_members,             /* tp_members */
    route_getset,              /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)route_init,      /* tp_init */
    0,                         /* tp_alloc */
    route_new,                 /* tp_new */
    0,                         /* tp_free */
    0                          /* tp_is_gc */
};
