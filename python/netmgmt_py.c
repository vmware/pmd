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

static char net__doc__[] = "";

static void
net_dealloc(
    PY_NET *self
    )
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
net_new(
    PyTypeObject *type,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    PPY_NET self = NULL;

    self = (PPY_NET)type->tp_alloc(type, 0);
    if (self != NULL)
    {
        if (!(self->server = PyBytes_FromString("")))
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
net_init(
    PY_NET *self,
    PyObject *args,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    PyObject *server = NULL;
    PyObject *tmp = NULL;

    static char *kwlist[] = {"server"};
    if (! PyArg_ParseTuple(args, "|S", &server))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    if (server)
    {
        tmp = self->server;
        Py_INCREF(server);
        self->server = server;
        Py_XDECREF(tmp);
    }

cleanup:
    return dwError > 0 ? -1 : 0;
error:
    goto cleanup;
}

static void
raise_javelin_exception(
    PPY_NET self,
    uint32_t dwPmdErrCode
    )
{
    uint32_t dwError = 0;
    char szErrMsg[MAX_LINE_LENGTH];

    // TODO: Improve this - get PMD err string
    sprintf(szErrMsg, "javelin error code=%u", dwPmdErrCode);
    PyErr_SetString(PyExc_Exception, szErrMsg);
    return;
}

static void
raise_netmgr_exception(
    PPY_NET self,
    uint32_t dwNmErrCode
    )
{
    uint32_t dwError = 0;
    char *pszErrInfo = NULL;
    char szErrMsg[MAX_LINE_LENGTH];

    if ((dwNmErrCode > NM_BASE_ERROR) && (dwNmErrCode < NM_MAX_ERROR))
    {
        dwError = netmgr_client_get_error_info(self->hHandle,
                                               dwNmErrCode,
                                               &pszErrInfo);
        BAIL_ON_PMD_ERROR(dwError);

        sprintf(szErrMsg,
                "netmgr error code=%u msg=%s",
                dwNmErrCode,
                pszErrInfo);
        PyErr_SetString(PyExc_Exception, szErrMsg);
    }
    else
    {
        raise_javelin_exception(self, dwNmErrCode);
    }

cleanup:
    PMDFreeMemory(pszErrInfo);
    return;
error:
    sprintf(szErrMsg,
            "javelin error code=%u raising netmgr exception for code=%u",
            dwError,
            dwNmErrCode);
    PyErr_SetString(PyExc_Exception, szErrMsg);
    goto cleanup;
}

static PyObject *
get_link_iaid(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t dwIaid = 0;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_dhcp_client_iaid(self->hHandle, pszInterfaceName, &dwIaid);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("i", dwIaid);

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_version(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszVersion = NULL;
    PyObject *pyRes = Py_None;

    dwError = netmgr_client_get_version(self->hHandle, &pszVersion);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", pszVersion);

cleanup:
    PMDFreeMemory(pszVersion);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
is_networkd_running(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszIsNetworkdRunning = NULL;
    PyObject *pyRes = Py_None;

    dwError = netmgr_client_is_networkd_running(self->hHandle, &pszIsNetworkdRunning);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", pszIsNetworkdRunning);

cleanup:
    PMDFreeMemory(pszIsNetworkdRunning);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_link_macaddr(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszMacAddr = NULL;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }


    dwError = netmgr_client_get_mac_addr(self->hHandle, pszInterfaceName, &pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", pszMacAddr);

cleanup:
    PMDFreeMemory(pszMacAddr);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
configure(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0;
    size_t argc = 0;
    size_t nCount = 0;
    char **ppszArgv = NULL;
    PyObject *pyRes = Py_None;
    PyObject *pArgvList = Py_None;

    dwError = py_object_as_py_list(arg, &pArgvList);
    BAIL_ON_PMD_ERROR(dwError);

    nCount = PyList_Size(pArgvList);
    if (nCount == 0)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = py_list_as_string_list(pArgvList,
                                     &ppszArgv,
                                     &argc);
    BAIL_ON_PMD_ERROR(dwError);
    if (nCount != argc)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = netmgr_client_configure(self->hHandle, argc, (const char **)ppszArgv);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    if (pArgvList != Py_None)
    {
        Py_DECREF(pArgvList);
    }
    PMDFreeStringArrayWithCount(ppszArgv, argc);
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_link_mtu(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t mtu;
    char *pszInterfaceName = NULL, *pszErr = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_link_mtu(self->hHandle, pszInterfaceName, &mtu);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("i", mtu);

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_link_Addresses(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char **ppszAddresses = NULL;
    PyObject *pPyAddressList = Py_None;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;
    PyObject *ptoAppend = Py_None;
    size_t nCount = 0;
    size_t i = 0;


    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_addresses(self->hHandle, pszInterfaceName, &nCount, &ppszAddresses);
    BAIL_ON_PMD_ERROR(dwError);

    pPyAddressList = PyList_New(0);
    for (i = 0; i < nCount; i++)
    {
        ptoAppend = Py_BuildValue("s", ppszAddresses[i]);
        if (PyList_Append(pPyAddressList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyRes = PyTuple_New(1);
    PyTuple_SetItem(pyRes, 0, pPyAddressList);

cleanup:
    PMDFreeStringArrayWithCount(ppszAddresses, nCount);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_link_Routes(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char **ppszRoutes = NULL;
    PyObject *pPyRoutesList = Py_None;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;
    PyObject *ptoAppend = Py_None;
    size_t nCount = 0;
    size_t i = 0;


    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_routes(self->hHandle, pszInterfaceName, &nCount, &ppszRoutes);
    BAIL_ON_PMD_ERROR(dwError);

    pPyRoutesList = PyList_New(0);
    for (i = 0; i < nCount; i++)
    {
        ptoAppend = Py_BuildValue("s", ppszRoutes[i]);
        if (PyList_Append(pPyRoutesList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyRes = PyTuple_New(1);
    PyTuple_SetItem(pyRes, 0, pPyRoutesList);

cleanup:
    PMDFreeStringArrayWithCount(ppszRoutes, nCount);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_dhcp_mode(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char **ppszRoutes = NULL;
    PyObject *pPyRoutesList = Py_None;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;
    uint32_t nDHCPMode = 0;
    size_t i = 0;


    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_dhcp_mode(
                        self->hHandle,
                        pszInterfaceName,
                        &nDHCPMode);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", py_net_dhcp_modes_to_name(nDHCPMode));

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_dns_servers(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char **ppszDnsServers = NULL;
    PyObject *pPyDnsServersList = Py_None;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;
    PyObject *ptoAppend = Py_None;

    dwError = netmgr_client_get_dns_servers(self->hHandle,
                                            &count,
                                            &ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pPyDnsServersList = PyList_New(0);
    for (i = 0; i < count; i++)
    {
        ptoAppend = Py_BuildValue("s", ppszDnsServers[i]);
        if (PyList_Append(pPyDnsServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyRes = PyTuple_New(1);
    PyTuple_SetItem(pyRes, 0, pPyDnsServersList);

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsServers, count);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_dns_domains(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char **ppszDnsDomains = NULL;
    PyObject *pPyDnsDomainsList = Py_None;
    PyObject *pyRes = Py_None;
    PyObject *ptoAppend = Py_None;

    dwError = netmgr_client_get_dns_domains(self->hHandle,
                                            &count,
                                            &ppszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    pPyDnsDomainsList = PyList_New(0);
    for (i = 0; i < count; i++)
    {
        ptoAppend = Py_BuildValue("s", ppszDnsDomains[i]);
        if (PyList_Append(pPyDnsDomainsList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyRes = pPyDnsDomainsList;

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsDomains, count);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_ntp_servers(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char **ppszNtpServers = NULL;
    PyObject *pPyNtpServersList = Py_None;
    PyObject *pyRes = Py_None;
    PyObject *ptoAppend = Py_None;
    static char *kwlist[] = {"ifname", NULL};

    if(!PyArg_ParseTupleAndKeywords(arg, kwds, "|s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_ntp_servers(self->hHandle,
                                            pszInterfaceName,
                                            &count,
                                            &ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    pPyNtpServersList = PyList_New(0);
    for (i = 0; i < count; i++)
    {
        ptoAppend = Py_BuildValue("s", ppszNtpServers[i]);
        if (PyList_Append(pPyNtpServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyRes = pPyNtpServersList;

cleanup:
    PMDFreeStringArrayWithCount(ppszNtpServers, count);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_system_network_info(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t j = 0;
    size_t countDnsServers = 0, countDnsDomains = 0, countNtpServers = 0;
    PPY_SYSTEM pPySystemObject = NULL;
    static char *kwlist[] = {"ifname", NULL};
    char **ppszDnsServers = NULL, **ppszDnsDomains = NULL;
    char **ppszNtpServers = NULL;
    char *pszInterfaceName = NULL;
    uint32_t nDHCPMode = 0;
    PyTypeObject *retType = &systemType;
    PyObject *ptoAppend = Py_None;
    PyObject *pPySystemInfoList = Py_None;
    PyObject *pPyDnsServersList = Py_None;
    PyObject *pPyDnsDomainsList = Py_None;
    PyObject *pPyNtpServersList = Py_None;
    PyObject *pyRes = Py_None;


    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPySystemObject = (PPY_SYSTEM)retType->tp_alloc(retType, 0);
    if (!pPySystemObject)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = netmgr_client_get_dns_servers(self->hHandle,
                                            &countDnsServers,
                                            &ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pPySystemInfoList = PyList_New(0);
    if (countDnsServers)
    {
        pPyDnsServersList = PyList_New(0);
    }
    for (j = 0; j < countDnsServers; j++)
    {
        ptoAppend = Py_BuildValue("s", ppszDnsServers[j]);
        if (PyList_Append(pPyDnsServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
    dwError = netmgr_client_get_dns_domains(self->hHandle,
                                            &countDnsDomains,
                                            &ppszDnsDomains);
    BAIL_ON_PMD_ERROR(dwError);

    if (countDnsDomains)
    {
        pPyDnsDomainsList = PyList_New(0);
    }
    for (j = 0; j < countDnsDomains; j++)
    {
        ptoAppend = Py_BuildValue("s", ppszDnsDomains[j]);
        if (PyList_Append(pPyDnsDomainsList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
    dwError = netmgr_client_get_ntp_servers(self->hHandle,
                                            pszInterfaceName,
                                            &countNtpServers,
                                            &ppszNtpServers);
    BAIL_ON_PMD_ERROR(dwError);

    if (countNtpServers)
    {
        pPyNtpServersList = PyList_New(0);
    }
    for (j = 0; j < countNtpServers; j++)
    {
        ptoAppend = Py_BuildValue("s", ppszNtpServers[j]);
        if (PyList_Append(pPyNtpServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_dhcp_mode(
                        self->hHandle,
                        pszInterfaceName,
                        &nDHCPMode);
    BAIL_ON_PMD_ERROR(dwError);

    pPySystemObject->pDnsMode = Py_BuildValue("s", py_net_dhcp_modes_to_name(nDHCPMode));
    pPySystemObject->pServersList = (PyObject *)pPyDnsServersList;
    pPySystemObject->pDomainsList = (PyObject *)pPyDnsDomainsList;
    pPySystemObject->pNtpServersList = (PyObject *)pPyNtpServersList;

    if (PyList_Append(pPySystemInfoList, (PyObject *)pPySystemObject) == -1)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pyRes = pPySystemInfoList;

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsServers, countDnsServers);
    PMDFreeStringArrayWithCount(ppszDnsDomains, countDnsDomains);
    PMDFreeStringArrayWithCount(ppszNtpServers, countNtpServers);
    return pyRes;

error:
    Py_XDECREF(pPySystemObject);
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_hostname(
    PPY_NET self,
    PyObject *arg
    )
{
    uint32_t dwError = 0, error = 0;
    PyObject *pPyResult = Py_None;
    char *pszHostname = NULL;

    dwError = netmgr_client_get_hostname(self->hHandle,
                                         &pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

    pPyResult = Py_BuildValue("s", pszHostname);

cleanup:
    PMDFreeMemory(pszHostname);
    return pPyResult;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyMethodDef net_methods[] =
{
    {"get_version", (PyCFunction)get_version,
     METH_VARARGS,
     "net.get_version()\" \n\
     gets network-config-manager API version. returns Version if successful, exception on failure.\n"},
    {"is_networkd_running", (PyCFunction)is_networkd_running,
     METH_VARARGS,
     "net.is_networkd_running() \" \n\
     check if networkd is running. returns Status if successful, exception on failure.\n"},
    {"get_link_iaid", (PyCFunction)get_link_iaid, METH_VARARGS|METH_KEYWORDS,
     "net.get_link_iaid(ifname = interface)\n\
     get interface iaid. returns IAID if successful, exception on failure.\n"},
    {"get_link_macaddr", (PyCFunction)get_link_macaddr,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_macaddr(ifname = interfacename\") \n\
     gets macaddress. returns MAC address if successful, exception on failure.\n"},
    {"configure", (PyCFunction)&configure, METH_VARARGS,
     "net.configure(argv) \n\
     configure network-config-manager. returns 0 if successful, exception on failure.\n"},
    {"get_link_mtu", (PyCFunction)get_link_mtu,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_mtu(ifname = interfacename\") \n\
     gets link mtu. returns link MTU if successful, exception on failure.\n"},
    {"get_link_Addresses", (PyCFunction)get_link_Addresses,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_Addresses(ifname = interfacename) \n\
     get addresses for the interface."
     "returns addresses if successful, exception on failure.\n"},
    {"get_link_Routes", (PyCFunction)get_link_Routes,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_Routes(ifname = interfacename) \n\
     get routes for the interface."
     "returns routes if successful, exception on failure.\n"},
    {"get_dhcp_mode", (PyCFunction)get_dhcp_mode,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_dhcp_mode(ifname = interfacename) \n\
     returns dhcp mode. "
     "returns dhcp mode if successful, exception on failure.\n"},
    {"get_dns_servers", (PyCFunction)get_dns_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_dns_servers() \n\
     get dns servers and the mode. returns dns servers, mode if successful, exception on failure.\n"},
    {"get_dns_domains", (PyCFunction)get_dns_domains,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_dns_domains() \n\
     get dns domains. returns dns domains if successful, exception on failure.\n"},
    {"get_ntp_servers", (PyCFunction)get_ntp_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_ntp_servers() \n\
     get ntp servers. returns NTP servers list if successful, exception on failure.\n"},
    {"get_system_network_info", (PyCFunction)get_system_network_info,
     METH_VARARGS|METH_KEYWORDS, "net.get_system_network_info(ifname = interfacename)\n\
     get network info common to the entire system.\n"},
    {"get_hostname", (PyCFunction)get_hostname,
     METH_VARARGS, "net.get_hostname()\n\
     returns hostname.\n"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef net_members[] =
{
    {"server", T_OBJECT_EX, offsetof(PY_NET, server), 0,
     "server details"},
    {NULL}  /* Sentinel */
};

static PyGetSetDef net_getset[] = {
    {NULL}  /* Sentinel */
};

PyTypeObject netType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "server.net",              /*tp_name*/
    sizeof(PY_NET),            /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)net_dealloc,   /*tp_dealloc*/
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
    net__doc__,                /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    net_methods,               /* tp_methods */
    net_members,               /* tp_members */
    net_getset,                /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)net_init,        /* tp_init */
    0,                         /* tp_alloc */
    net_new,                   /* tp_new */
    0,                         /* tp_free */
    0,                         /* tp_is_gc */
};
