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

char rolemgmt_logentry__doc__[] = "";

void
rolemgmt_logentry_dealloc(PY_ROLEMGMT_LOG_ENTRY *self)
{
    Py_XDECREF(self->log);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

PyObject *
rolemgmt_logentry_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds)
{
    uint32_t dwError = 0;
    PPY_ROLEMGMT_LOG_ENTRY self = NULL;

    self = (PPY_ROLEMGMT_LOG_ENTRY)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        self->tStamp = 0;
        if(!(self->log = PyBytes_FromString("")))
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
rolemgmt_logentry_init(
    PY_ROLEMGMT_LOG_ENTRY *self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    long tStamp = 0;
    PyObject *log = NULL;
    PyObject *tmp = NULL;

    static char *kwlist[] = {"tstamp", "log", NULL};

    if (!PyArg_ParseTupleAndKeywords(
              args, kwds, "|iS", kwlist,
              &tStamp, &log))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (log)
    {
        tmp = self->log;
        Py_INCREF(log);
        self->log = log;
        Py_XDECREF(tmp);
    }

cleanup:
    return dwError > 0 ? -1 : 0;

error:
    fprintf(stderr, "Error = %d\n", dwError);
    goto cleanup;
}

PyObject*
rolemgmt_logentry_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_ROLEMGMT_LOG_ENTRY pLogEntry = NULL;
    char *pszRepr = NULL;

    pLogEntry = (PPY_ROLEMGMT_LOG_ENTRY)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{tstamp: %ld, log: %s}",
                  pLogEntry->tStamp,
                  pLogEntry->log ? PyBytes_AsString(pLogEntry->log) : "");
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
rolemgmt_logentry_str(
    PyObject *self
    )
{
    return rolemgmt_logentry_repr(self);
}

uint32_t
rolemgmt_logentry_py_make(
    PPMD_ROLEMGMT_TASK_LOG pLogEntry,
    PPY_ROLEMGMT_LOG_ENTRY *ppPyLogEntry
    )
{
    uint32_t dwError = 0;
    PPY_ROLEMGMT_LOG_ENTRY pPyLogEntry = NULL;
    PyTypeObject *retType = &rolemgmt_logentryType;
    struct tm *pTime = NULL;

    if(!pLogEntry || !ppPyLogEntry)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyLogEntry = (PPY_ROLEMGMT_LOG_ENTRY)retType->tp_alloc(retType, 0);
    if(!pPyLogEntry)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pTime = gmtime(&pLogEntry->tStamp);
    if(!pTime)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

printf("before time:%d:%d:%d\n", pTime->tm_hour, pTime->tm_min, pTime->tm_sec);
/*
    pPyLogEntry->tstamp = PyTime_FromTime(
                              0, 
                              0, 
                              0, 
                              0); 
*/
printf("after time\n");
    pPyLogEntry->log = PyBytes_FromString(pLogEntry->pszLog);

    *ppPyLogEntry = pPyLogEntry;
cleanup:
    return dwError;

error:
    Py_XDECREF(pPyLogEntry);
    pPyLogEntry = NULL;
    goto cleanup;
}

static PyGetSetDef rolemgmt_logentry_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef rolemgmt_logentry_methods[] = {
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef rolemgmt_logentry_members[] = {
    {"tStamp", T_OBJECT_EX, offsetof(PY_ROLEMGMT_LOG_ENTRY, tStamp), 0,
     "log date time"},
    {"log", T_OBJECT_EX, offsetof(PY_ROLEMGMT_LOG_ENTRY, log), 0,
     "log data"},
    {NULL}  /* Sentinel */
};

PyTypeObject rolemgmt_logentryType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "rolemgmt_logentry",            /*tp_name*/
    sizeof(PY_ROLEMGMT_LOG_ENTRY),  /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)rolemgmt_logentry_dealloc,/*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    rolemgmt_logentry_repr,         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    rolemgmt_logentry_str,          /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    rolemgmt_logentry__doc__,       /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    rolemgmt_logentry_methods,      /* tp_methods */
    rolemgmt_logentry_members,      /* tp_members */
    rolemgmt_logentry_getset,       /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)rolemgmt_logentry_init,   /* tp_init */
    0,                         /* tp_alloc */
    rolemgmt_logentry_new,          /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
