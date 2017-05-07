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

static char firewall__doc__[] = "";

static void
firewall_dealloc(
    PY_FIREWALL *self
    )
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
firewall_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds
    )
{
    PPY_FIREWALL self = NULL;

    self = (PPY_FIREWALL)type->tp_alloc(type, 0);
    if (self != NULL)
    {
    }

    return (PyObject *)self;
}

static int
firewall_init(
    PY_FIREWALL *self,
    PyObject *args,
    PyObject *kwds
    )
{
    PyObject *pFirewall = NULL;

    if (! PyArg_ParseTuple(args, "O", &pFirewall))
    {
        return -1;
    }

    return 0;
}

PyObject*
firewall_get_rules(
    PPY_FIREWALL self,
    void *closure)
{
    uint32_t dwError = 0;
    size_t nCount = 0;
    size_t i = 0;
    PPMD_FIREWALL_RULE pRules = NULL;
    PPMD_FIREWALL_RULE pRule = NULL;
    PyObject *pyRulesList = Py_None;

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pyRulesList = PyList_New(0);

    dwError = fwmgmt_get_rules(self->hHandle, 0, &pRules);
    BAIL_ON_PMD_ERROR(dwError);

    for(pRule = pRules; pRule; pRule = pRule->pNext)
    {
        PyObject *pyRule = Py_None;
        pyRule = PyBytes_FromString(pRule->pszRule);
        if(PyList_Append(pyRulesList, pyRule) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

cleanup:
    fwmgmt_free_rules(pRules);
    return pyRulesList;

error:
    pyRulesList = Py_None;
    goto cleanup;
}

static PyGetSetDef firewall_getset[] = {
    {"rules",
     (getter)firewall_get_rules, (setter)NULL,
     "get firewall rules",
     NULL},
    {NULL}  /* Sentinel */
};

static PyObject *
add_rule(
    PPY_FIREWALL self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    int nPersist = 0;
    char *pszChain= NULL;
    char *pszRuleSpec = NULL;
    PyObject *ppyPersist = NULL;
    PyObject *ppyIPV6 = NULL;
    int nIPV6 = 0;
    static char *kwlist[] = {"chain", "rule", "persist", "ipv6", NULL};

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "ss|O!O!", kwlist,
             &pszChain,
             &pszRuleSpec,
             &PyBool_Type,
             &ppyPersist,
             &PyBool_Type,
             &ppyIPV6))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(ppyPersist && PyObject_IsTrue(ppyPersist))
    {
        nPersist = 1;
    }

    if(ppyIPV6 && PyObject_IsTrue(ppyIPV6))
    {
        nIPV6 = 1;
    }
    dwError = fwmgmt_add_rule(self->hHandle,
                              nIPV6,
                              nPersist,
                              pszChain,
                              pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return Py_BuildValue("i", dwError);

error:
    goto cleanup;
}

static PyObject *
delete_rule(
    PPY_FIREWALL self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    int nPersist = 0;
    char *pszChain= NULL;
    char *pszRuleSpec = NULL;
    PyObject *ppyPersist = NULL;
    PyObject *ppyIPV6 = NULL;
    int nIPV6 = 0;
    static char *kwlist[] = {"chain", "rule", "persist", "ipv6", NULL};

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "ss|O!O!", kwlist,
             &pszChain,
             &pszRuleSpec,
             &PyBool_Type,
             &ppyPersist,
             &PyBool_Type,
             &ppyIPV6))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(ppyPersist && PyObject_IsTrue(ppyPersist))
    {
        nPersist = 1;
    }

    if(ppyIPV6 && PyObject_IsTrue(ppyIPV6))
    {
        nIPV6 = 1;
    }
    dwError = fwmgmt_delete_rule(self->hHandle,
                                 nIPV6,
                                 nPersist,
                                 pszChain,
                                 pszRuleSpec);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    return Py_BuildValue("i", dwError);

error:
    goto cleanup;
}

uint32_t
get_cmds(
    PyObject *pyList,
    PPMD_FIREWALL_CMD *ppCmds
    )
{
    uint32_t dwError = 0;
    size_t i = 0;
    size_t nCount = 0;
    PPMD_FIREWALL_CMD pCmds = NULL;
    PPMD_FIREWALL_CMD pCmd = NULL;

    if(!pyList || !ppCmds)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    nCount = PyList_Size(pyList);
    if(nCount == 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    for(i = 0; i < nCount; ++i)
    {
        PyObject *pyItem = NULL;
        char *pszItem = NULL;
        pyItem = PyList_GetItem(pyList, i);

        dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_CMD), (void **)&pCmd);
        BAIL_ON_PMD_ERROR(dwError);

        pszItem = PyBytes_AsString(pyItem);
        if(!pszItem)
        {
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_PMD_ERROR(dwError);
        }

        dwError = PMDAllocateString(pszItem, &pCmd->pszRawCmd);
        BAIL_ON_PMD_ERROR(dwError);

        if(!pCmds)
        {
            pCmds = pCmd;
        }
        else
        {
            PPMD_FIREWALL_CMD pTemp = pCmds;
            while(pTemp && pTemp->pNext) pTemp = pTemp->pNext;
            pTemp->pNext = pCmd;
        }
        pCmd = NULL;
    }

    *ppCmds = pCmds;
cleanup:
    return dwError;

error:
    if(ppCmds)
    {
        *ppCmds = NULL;
    }
    fwmgmt_free_cmd(pCmd);
    fwmgmt_free_cmd(pCmds);
    goto cleanup;
}

static
uint32_t
get_table(
    PyObject *pKey,
    PyObject *pValue,
    PPMD_FIREWALL_TABLE *ppTable
    )
{
    uint32_t dwError = 0;
    PPMD_FIREWALL_TABLE pTable = NULL;
    char *pszTemp = NULL;

    if(!pKey || !pValue || !ppTable)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateMemory(sizeof(PMD_FIREWALL_TABLE), (void **)&pTable);
    BAIL_ON_PMD_ERROR(dwError);

    pszTemp = PyBytes_AsString(pKey);

    if(IsNullOrEmptyString(pszTemp))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = PMDAllocateString(pszTemp, &pTable->pszName);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = get_cmds(pValue, &pTable->pCmds);
    BAIL_ON_PMD_ERROR(dwError);

    *ppTable = pTable;

cleanup:
    return dwError;

error:
    if(ppTable)
    {
        *ppTable = NULL;
    }
    fwmgmt_free_table(pTable);
    goto cleanup;
}

static PyObject *
restore(
    PPY_FIREWALL self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    static char *kwlist[] = {"tables", "ipv6", NULL};
    PyObject *ppyTables = NULL;
    PPMD_FIREWALL_TABLE pTable = NULL;
    PPMD_FIREWALL_TABLE pTempTable = NULL;
    PPMD_FIREWALL_CMD pCmd = NULL;
    PyObject *ppyIPV6 = NULL;
    int nIPV6 = 0;

    PyObject *key, *value;
    Py_ssize_t pos = 0;

    if(!self || !self->hHandle)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!PyArg_ParseTupleAndKeywords(
             arg, kwds, "O!|O!", kwlist,
             &PyDict_Type,
             &ppyTables,
             &PyBool_Type,
             &ppyIPV6))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if(ppyIPV6 && PyObject_IsTrue(ppyIPV6))
    {
        nIPV6 = 1;
    }

    while (PyDict_Next(ppyTables, &pos, &key, &value))
    {
        dwError = get_table(key, value, &pTempTable);
        BAIL_ON_PMD_ERROR(dwError);

        if(!pTable)
        {
            pTable = pTempTable;
        }
        else
        {
            PPMD_FIREWALL_TABLE pTemp = pTable;
            while(pTemp && pTemp->pNext) pTemp = pTemp->pNext;
            pTemp->pNext = pTempTable;
        }
        pTempTable = NULL;
    }

    dwError = fwmgmt_restore(self->hHandle, nIPV6, pTable);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    fwmgmt_free_table(pTable);
    return Py_BuildValue("i", dwError);

error:
    fwmgmt_free_table(pTempTable);
    goto cleanup;
}

static PyMethodDef firewall_methods[] =
{
    {"add_rule", (PyCFunction)add_rule, METH_VARARGS|METH_KEYWORDS,
     "firewall.add_rule(chain='INPUT', rule='-p tcp --dport 80 -j ACCEPT') \n\
     adds the rule.\n\
     set optional persist to True if the rule needs to be applied on restart.\n\
     set optional ipv6 to True if the rule needs to be applied for ipv6.\n\
     returns 0 if successful.\n"},
    {"delete_rule", (PyCFunction)delete_rule, METH_VARARGS|METH_KEYWORDS,
     "firewall.delete_rule(chain='INPUT', rule='-p tcp --dport 80 -j ACCEPT') \n\
     deletes the rule.\n\
     set optional persist to True if the rule needs to be applied on restart.\n\
     set optional ipv6 to True if the rule needs to be applied for ipv6.\n\
     returns 0 if successful.\n"},
    {"restore", (PyCFunction)restore, METH_VARARGS|METH_KEYWORDS,
     "tables = {}\n\
     cmds = ['-P PREROUTING ACCEPT', '-P INPUT ACCEPT']x.\n\
     tables['nat'] = cmds\n\
     firewall.restore(tables)\n\
     runs batch commands iptables-restore.\n\
     returns 0 if successful.\n"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef firewall_members[] =
{
    {NULL}  /* Sentinel */
};

PyTypeObject firewallType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "server.firewall",         /*tp_name*/
    sizeof(PY_FIREWALL),       /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)firewall_dealloc, /*tp_dealloc*/
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
    firewall__doc__,           /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    firewall_methods,          /* tp_methods */
    firewall_members,          /* tp_members */
    firewall_getset,           /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)firewall_init,   /* tp_init */
    0,                         /* tp_alloc */
    firewall_new,              /* tp_new */
    0,                         /* tp_free */
    0                          /* tp_is_gc */
};
