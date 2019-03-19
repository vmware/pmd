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

static char rolemgmt__doc__[] = "";

static void
rolemgmt_dealloc(
    PY_ROLEMGMT *self
    )
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
rolemgmt_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds
    )
{
    PPY_ROLEMGMT self = NULL;

    self = (PPY_ROLEMGMT)type->tp_alloc(type, 0);
    if (self != NULL)
    {
    }

    return (PyObject *)self;
}

static int
rolemgmt_init(
    PY_ROLEMGMT *self,
    PyObject *args,
    PyObject *kwds
    )
{
    PyObject *pRoles = NULL;

    if (! PyArg_ParseTuple(args, "O", &pRoles))
    {
        return -1;
    }

    return 0;
}

PyObject*
rolemgmt_py_get_version(
    PPY_ROLEMGMT self,
    void *closure)
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    PyObject *pyVersion = Py_None;

    dwError = rolemgmt_get_version(self->hHandle, &pszVersion);
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
    raise_exception(dwError);
    goto cleanup;
}

PyObject*
rolemgmt_py_get_roles(
    PPY_ROLEMGMT self,
    void *closure)
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    PPMD_ROLEMGMT_ROLE pRoles = NULL;
    PPMD_ROLEMGMT_ROLE pRole = NULL;
    PyObject *pPyRolesDict = Py_None;

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRolesDict = PyDict_New();

    dwError = rolemgmt_get_roles(self->hHandle, &pRoles);
    BAIL_ON_PMD_ERROR(dwError);

    for(pRole = pRoles; pRole; pRole = pRole->pNext)
    {
        PyObject *pPyRoleDict = Py_None;
        PyObject *pPyRoleId = PyBytes_FromString(pRole->pszId);

        dwError = rolemgmt_role_py_make(pRole, &pPyRoleDict);
        BAIL_ON_PMD_ERROR(dwError);

        if(PyDict_SetItem(pPyRolesDict, pPyRoleId, pPyRoleDict) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    rolemgmt_free_roles(pRoles);
    return pPyRolesDict;

error:
    pPyRolesDict = NULL;
    raise_exception(dwError);
    goto cleanup;
}

PyObject *
rolemgmt_py_role_version(
    PPY_ROLEMGMT self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszRoleName = NULL;
    char *pszRoleVersion = NULL;
    static char *kwlist[] = {"name", NULL};
    PyObject *pyRoleVersion = Py_None;

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "s", kwlist,
             &pszRoleName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_get_role_version(
                  self->hHandle,
                  pszRoleName,
                  &pszRoleVersion);
    BAIL_ON_PMD_ERROR(dwError);

    pyRoleVersion = PyBytes_FromString(pszRoleVersion);
    if(!pyRoleVersion)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

cleanup:
    return pyRoleVersion;

error:
    pyRoleVersion = NULL;
    raise_exception(dwError);
    goto cleanup;
}

PyObject *
rolemgmt_py_prereqs(
    PPY_ROLEMGMT self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszRoleName = NULL;
    PPMD_ROLE_PREREQ pPrereqs = NULL;
    uint32_t i = 0;
    uint32_t dwPrereqCount = 0;
    PMD_ROLE_OPERATION nOperation = ROLE_OPERATION_NONE;
    static char *kwlist[] = {"name", NULL};
    PPY_ROLEMGMT_PREREQ pPyPrereq = NULL;
    PyObject *pyPrereqList = NULL;

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "s", kwlist,
             &pszRoleName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_get_prereqs(
                  self->hHandle,
                  pszRoleName,
                  nOperation,
                  &pPrereqs,
                  &dwPrereqCount);
    BAIL_ON_PMD_ERROR(dwError);

    pyPrereqList = PyList_New(0);

    for(i = 0; i < dwPrereqCount; ++i)
    {
        dwError = rolemgmt_prereq_py_make(
                      &pPrereqs[i],
                      &pPyPrereq);
        BAIL_ON_PMD_ERROR(dwError);

        if(PyList_Append(pyPrereqList, (PyObject *)pPyPrereq) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    return pyPrereqList;

error:
    pyPrereqList = NULL;
    raise_exception(dwError);
    goto cleanup;
}

PyObject *
rolemgmt_py_task_status(
    PPY_ROLEMGMT self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszRoleName = NULL;
    char *pszTaskUUID = NULL;
    static char *kwlist[] = {"name", "taskid", NULL};
    PyObject *pyTaskStatus = Py_None;
    PMD_ROLE_STATUS nStatus = ROLE_STATUS_NONE;

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "ss", kwlist,
             &pszRoleName, &pszTaskUUID))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_get_status(
                  self->hHandle,
                  pszRoleName,
                  pszTaskUUID,
                  &nStatus);
    BAIL_ON_PMD_ERROR(dwError);

    pyTaskStatus = Py_BuildValue("i", nStatus);

cleanup:
    return pyTaskStatus;

error:
    pyTaskStatus = NULL;
    raise_exception(dwError);
    goto cleanup;
}

PyObject *
rolemgmt_py_alter(
    PPY_ROLEMGMT self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszRoleName = NULL;
    char *pszConfig = NULL;
    PMD_ROLE_OPERATION nOperation = ROLE_OPERATION_NONE;
    char *pszTaskUUID = NULL;
    PyObject *pyTaskID = NULL;
    static char *kwlist[] = {"name", "operation", "config", NULL};

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "sIs", kwlist,
             &pszRoleName, &nOperation, &pszConfig))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(nOperation <= ROLE_OPERATION_NONE || nOperation >= ROLE_OPERATION_MAX)
    {
        dwError = ERROR_PMD_ROLE_BAD_OPERATION;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_alter(
                  self->hHandle,
                  pszRoleName,
                  nOperation,
                  pszConfig,
                  &pszTaskUUID);
    BAIL_ON_PMD_ERROR(dwError);

    pyTaskID = PyBytes_FromString(pszTaskUUID);

cleanup:
    return pyTaskID;

error:
    pyTaskID = NULL;
    raise_exception(dwError);
    goto cleanup;
}

PyObject *
rolemgmt_py_logs(
    PPY_ROLEMGMT self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t i = 0;
    char *pszTaskUUID = NULL;
    int nStartAt = 0;
    int nNumLogs = 0;
    PPMD_ROLEMGMT_TASK_LOG pTaskLogs = NULL;
    uint32_t dwLogCount = 0;
    PyObject *pyTaskLogList = NULL;
    PPY_ROLEMGMT_LOG_ENTRY pPyLogEntry = NULL;

    static char *kwlist[] = {"taskid", "startat", "numlogs", NULL};

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "sII", kwlist,
             &pszTaskUUID, &nStartAt, &nNumLogs))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = rolemgmt_get_log(
                  self->hHandle,
                  pszTaskUUID,
                  nStartAt,
                  nNumLogs,
                  &pTaskLogs,
                  &dwLogCount);
    BAIL_ON_PMD_ERROR(dwError);

    pyTaskLogList = PyList_New(0);

    for(i = 0; i < dwLogCount; ++i)
    {
printf("i = %d\n", i);
        dwError = rolemgmt_logentry_py_make(
                      &pTaskLogs[i],
                      &pPyLogEntry);
        BAIL_ON_PMD_ERROR(dwError);
printf("i = %d\n", i);

        if(PyList_Append(pyTaskLogList, (PyObject *)pPyLogEntry) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    return pyTaskLogList;

error:
    pyTaskLogList = NULL;
    raise_exception(dwError);
    goto cleanup;
}

static PyGetSetDef rolemgmt_getset[] = {
    {"version",
     (getter)rolemgmt_py_get_version, (setter)NULL,
     "get rolemgmt version",
     NULL},
    {"roles",
     (getter)rolemgmt_py_get_roles, (setter)NULL,
     "get all registered roles",
     NULL},
    {NULL}  /* Sentinel */
};

static PyMethodDef rolemgmt_methods[] =
{
    {"role_version", (PyCFunction)rolemgmt_py_role_version, METH_VARARGS|METH_KEYWORDS,
     "rolemgmt.role_version(name=<role name>) \n\
     returns the version of a role by making a query to the plugin.\n\
     returns version if successful.\n"},
    {"prereqs", (PyCFunction)rolemgmt_py_prereqs, METH_VARARGS|METH_KEYWORDS,
     "rolemgmt.prereqs(name=<role name>) \n\
     returns the prereqs of a role by making a query to the plugin.\n\
     returns list of prereqs if successful.\n"},
    {"status", (PyCFunction)rolemgmt_py_task_status, METH_VARARGS|METH_KEYWORDS,
     "rolemgmt.status(name=<role name>, taskid=<task uuid>) \n\
     returns the status a role's task at the server.\n\
     returns status of role's task if successful.\n"},
    {"alter", (PyCFunction)rolemgmt_py_alter, METH_VARARGS|METH_KEYWORDS,
     "rolemgmt.alter(name=<role name>,operation=<operation>,config=<config json>) \n\
     run the alter operation of a role at the server.\n\
     return new task id if successful.\n"},
    {"logs", (PyCFunction)rolemgmt_py_logs, METH_VARARGS|METH_KEYWORDS,
     "rolemgmt.logs(taskid=<task uuid>,startat=<start at>,count=<number of entries to fetch>) \n\
     returns logs from an index for a task running at the server.\n\
     return logs if successful.\n"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef rolemgmt_members[] =
{
    {NULL}  /* Sentinel */
};

PyTypeObject rolemgmtType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "server.rolemgmt",         /*tp_name*/
    sizeof(PY_ROLEMGMT),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)rolemgmt_dealloc, /*tp_dealloc*/
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
    rolemgmt__doc__,              /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    rolemgmt_methods,          /* tp_methods */
    rolemgmt_members,          /* tp_members */
    rolemgmt_getset,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)rolemgmt_init,   /* tp_init */
    0,                         /* tp_alloc */
    rolemgmt_new,              /* tp_new */
    0,                         /* tp_free */
    0                          /* tp_is_gc */
};
