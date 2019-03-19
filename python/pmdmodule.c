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

static char pmd__doc__[] = "";

static int
prepareInitModule(
    )
{
    if (PyType_Ready(&serverType) < 0) return 0;
    if (PyType_Ready(&netType) < 0) return 0;
    if (PyType_Ready(&linkType) < 0) return 0;
    if (PyType_Ready(&systemType) < 0) return 0;
    if (PyType_Ready(&routeType) < 0) return 0;
    if (PyType_Ready(&firewallType) < 0) return 0;
    if (PyType_Ready(&pkgType) < 0) return 0;
    if (PyType_Ready(&repodataType) < 0) return 0;
    if (PyType_Ready(&packageType) < 0) return 0;
    if (PyType_Ready(&solvedInfoType) < 0) return 0;
    if (PyType_Ready(&rolemgmtType) < 0) return 0;
    if (PyType_Ready(&rolemgmt_roleType) < 0) return 0;
    if (PyType_Ready(&rolemgmt_prereqType) < 0) return 0;
    if (PyType_Ready(&rolemgmt_logentryType) < 0) return 0;

    return 1;
}

static PyMethodDef pmdMethods[] =
{
    {NULL}  /* Sentinel */
};

static int
initModule(
    PyObject *pModule
    )
{
    Py_INCREF(&serverType);
    PyModule_AddObject(pModule, "server", (PyObject *) &serverType);

    return 1;
}

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef pmdModule =
{
    PyModuleDef_HEAD_INIT,
    "_pmd",   /* name of module */
    pmd__doc__, /* module documentation, may be NULL */
    0,           /* m_size */
    pmdMethods
};

PyObject *
PyInit__pmd(
     )
{
    PyObject *pModule = NULL;

    if (!prepareInitModule())
        return NULL;

    pModule = PyModule_Create(&pmdModule);
    if(!pModule)
    {
        goto error;
    }

    if(!initModule(pModule))
    {
        goto error;
    }

cleanup:
    return pModule;

error:
    if(pModule)
    {
        Py_XDECREF(pModule);
    }
    pModule = NULL;
    goto cleanup;
}

int
main(
    int argc,
    char *argv[]
    )
{
    wchar_t *program = Py_DecodeLocale(argv[0], NULL);
    if (program == NULL) {
        fprintf(stderr, "Fatal error: cannot decode argv[0]\n");
        exit(1);
    }

    /* Add a built-in module, before Py_Initialize */
    PyImport_AppendInittab("_pmd", PyInit__pmd);

    /* Pass argv[0] to the Python interpreter */
    Py_SetProgramName(program);

    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Optionally import the module; alternatively,
       import can be deferred until the embedded script
       imports it. */
    PyImport_ImportModule("_pmd");

    PyMem_RawFree(program);
    return 0;
}

#else

PyMODINIT_FUNC
init_pmd(
    )
{
    PyObject *pModule = NULL;

    if (!prepareInitModule())
        return;

    pModule = Py_InitModule3("_pmd", pmdMethods, pmd__doc__);
    if(pModule)
    {
        initModule(pModule);
    }
}

int
main(
    int argc,
    char *argv[]
    )
{
    /* Pass argv[0] to the Python interpreter */
    Py_SetProgramName(argv[0]);


    /* Initialize the Python interpreter.  Required. */
    Py_Initialize();

    /* Add a static module */
    init_pmd();

    return 0;
}

#endif
