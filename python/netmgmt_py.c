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
net_dealloc(PY_NET *self)
{
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
net_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
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
net_init(PY_NET *self, PyObject *args, PyObject *kwds)
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
set_link_iaid(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t dwIaid = 0;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", "iaid", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sI",
                                     kwlist,
                                     &pszInterfaceName,
                                     &dwIaid))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_iaid(self->hHandle, pszInterfaceName, dwIaid);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
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

    dwError = netmgr_client_get_iaid(self->hHandle, pszInterfaceName, &dwIaid);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("i", dwIaid);

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_dhcp_duid(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszDuid = NULL;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"duid", "ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s|s",
                                     kwlist,
                                     &pszDuid,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_duid(self->hHandle, pszInterfaceName, pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_dhcp_duid(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszDuid = NULL;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if(!PyArg_ParseTupleAndKeywords(arg, kwds, "|s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_duid(self->hHandle, pszInterfaceName, &pszDuid);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", pszDuid);

cleanup:
    PMDFreeMemory(pszDuid);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_link_macaddr(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char  *pszInterfaceName = NULL;
    char *pszMacAddr = NULL;
    static char *kwlist[] = {"ifname", "macaddr", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sz",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszMacAddr))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_mac_addr(self->hHandle,
                                         pszInterfaceName,
                                         pszMacAddr);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
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
set_link_mtu(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, mtu = 0;
    char  *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", "mtu", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sI",
                                     kwlist,
                                     &pszInterfaceName,
                                     &mtu))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_link_mtu(self->hHandle, pszInterfaceName, mtu);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
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
set_link_mode(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    int link_mode = LINK_MODE_UNKNOWN;
    char *pszLinkMode = NULL;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", "link_mode", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszLinkMode))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!strcmp(pszLinkMode, "manual"))
    {
        link_mode = LINK_MANUAL;
    }
    else if (!strcmp(pszLinkMode, "auto"))
    {
        link_mode = LINK_AUTO;
    }
    else 
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_link_mode(self->hHandle,
                                          pszInterfaceName,
                                          link_mode);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_link_mode(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    NET_LINK_MODE mode;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_link_mode(self->hHandle, pszInterfaceName, &mode);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", py_link_mode_to_string(mode));

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_link_state(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    int link_state = LINK_STATE_UNKNOWN;
    char *pszInterfaceName = NULL;
    char *pszLinkState = NULL;
    static char *kwlist[] = {"ifname", "link_state", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszLinkState))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!strcmp(pszLinkState, "up"))
    {
        link_state = LINK_UP;
    }
    else if (!strcmp(pszLinkState, "down"))
    {
        link_state = LINK_DOWN;
    }
    else
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_link_state(self->hHandle,
                                           pszInterfaceName,
                                           link_state);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_link_state(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    NET_LINK_STATE state;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_link_state(self->hHandle, pszInterfaceName, &state);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", py_link_state_to_string(state));

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_link_up(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char  *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s",
                                     kwlist,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_ifup(self->hHandle, pszInterfaceName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_link_down(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char  *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s",
                                     kwlist,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_ifdown(self->hHandle, pszInterfaceName);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_ipv4_addr_gateway(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char  *pszInterfaceName = NULL;
    int ip4Mode = IPV4_ADDR_MODE_MAX;
    char *pszMode = NULL;
    char *pszIPv4AddrPrefix = NULL;
    char *pszIPv4Gateway = NULL;
    static char *kwlist[] = {"ifname",
                             "addr_mode",
                             "addr_prefix",
                             "gateway",
                             NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss|s|s",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszMode,
                                     &pszIPv4AddrPrefix,
                                     &pszIPv4Gateway))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!strcmp(pszMode, "dhcp"))
    {
        ip4Mode = IPV4_ADDR_MODE_DHCP;
    }
    else if (!strcmp(pszMode, "static"))
    {
        ip4Mode = IPV4_ADDR_MODE_STATIC;
    }
    else if (!strcmp(pszMode, "none"))
    {
        ip4Mode = IPV4_ADDR_MODE_NONE;
    }
    else
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_ipv4_addr_gateway(self->hHandle,
                                                  pszInterfaceName,
                                                  ip4Mode,
                                                  pszIPv4AddrPrefix,
                                                  pszIPv4Gateway);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_ipv4_addr_gateway(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    NET_IPV4_ADDR_MODE addrMode = IPV4_ADDR_MODE_NONE;
    char *pszIPv4AddrPrefix = NULL;
    char *pszIPv4Gateway = NULL;
    char *pszAddrMode = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_ipv4_addr_gateway(self->hHandle,
                                                  pszInterfaceName,
                                                  &addrMode,
                                                  &pszIPv4AddrPrefix,
                                                  &pszIPv4Gateway);
    BAIL_ON_PMD_ERROR(dwError);

    if (addrMode == IPV4_ADDR_MODE_NONE)
    {
        pszAddrMode = "none";
    }
    else if (addrMode == IPV4_ADDR_MODE_DHCP)
    {
        pszAddrMode = "dhcp";
    }
    else
    {
        pszAddrMode = "static";
    }

    pyRes = PyTuple_New(3);
    PyTuple_SetItem(pyRes, 0, Py_BuildValue("s", pszAddrMode));
    PyTuple_SetItem(pyRes, 1, Py_BuildValue("s", pszIPv4AddrPrefix));
    PyTuple_SetItem(pyRes, 2, Py_BuildValue("s", pszIPv4Gateway));

cleanup:
    PMDFreeMemory(pszIPv4AddrPrefix);
    PMDFreeMemory(pszIPv4Gateway);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
add_static_ipv6_addr(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char *pszIPv6AddrPrefix = NULL;
    static char *kwlist[] = {"ifname", "addr_prefix", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszIPv6AddrPrefix))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_add_static_ipv6_addr(self->hHandle,
                                                 pszInterfaceName,
                                                 pszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
delete_static_ipv6_addr(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char *pszIPv6AddrPrefix = NULL;
    static char *kwlist[] = {"ifname", "addr_prefix", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszIPv6AddrPrefix))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_delete_static_ipv6_addr(self->hHandle,
                                                    pszInterfaceName,
                                                    pszIPv6AddrPrefix);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_ipv6_addr(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t j, count = 0;
    uint32_t addrTypes = DHCP_IPV6 | AUTO_IPV6 | STATIC_IPV6;
    char *pszInterfaceName = NULL;
    char *pszType = NULL;
    NET_IP_ADDR **ppipaddrList = NULL;
    static char *kwlist[] = {"ifname", "type", NULL};
    PyObject *pyRes = Py_None;
    PyObject *pPyIpv6AddrList = PyList_New(0);

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s|s",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszType))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (pszType != NULL)
    {
        addrTypes = 0;
        if (strcasestr(pszType, "dhcp"))
        {
            addrTypes |= DHCP_IPV6;
        }
        if (strcasestr(pszType, "static"))
        {
            addrTypes |= STATIC_IPV6;
        }
        if (strcasestr(pszType, "autoconf"))
        {
            addrTypes |= AUTO_IPV6;
        }
        if (strcasestr(pszType, "linklocal"))
        {
            addrTypes |= LINK_LOCAL_IPV6;
        }
    }

    dwError = netmgr_client_get_ip_addr(self->hHandle,
                                        pszInterfaceName,
                                        addrTypes,
                                        &count,
                                        &ppipaddrList);
    if (dwError == NM_ERR_VALUE_NOT_FOUND)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    for (j = 0; j < count; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppipaddrList[j]->pszIPAddrPrefix);
        if (PyList_Append(pPyIpv6AddrList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyRes = pPyIpv6AddrList;

cleanup:
    if (ppipaddrList)
    {
        for (j = 0; j < count; j++)
        {
            PMDFreeMemory(ppipaddrList[j]->pszInterfaceName);
            PMDFreeMemory(ppipaddrList[j]->pszIPAddrPrefix);
            PMDFreeMemory(ppipaddrList[j]);
        }
        PMDFreeMemory(ppipaddrList);
    }
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_ipv6_addr_mode(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t enableDhcp = 0;
    uint32_t enableAutoconf = 0;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname",
                             "enable_dhcp",
                             "enable_autoconf",
                             NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sii",
                                     kwlist,
                                     &pszInterfaceName,
                                     &enableDhcp,
                                     &enableAutoconf))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_ipv6_addr_mode(self->hHandle,
                                               pszInterfaceName,
                                               enableDhcp,
                                               enableAutoconf);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_ipv6_addr_mode(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    uint32_t enableDhcp = 0;
    uint32_t enableAutoconf = 0;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg, kwds, "s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_ipv6_addr_mode(self->hHandle,
                                               pszInterfaceName,
                                               &enableDhcp,
                                               &enableAutoconf);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = PyTuple_New(2);
    PyTuple_SetItem(pyRes, 0, Py_BuildValue("i", enableDhcp));
    PyTuple_SetItem(pyRes, 1, Py_BuildValue("i", enableAutoconf));

cleanup:
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_ipv6_gateway(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char *pszIPv6Gateway = NULL;
    static char *kwlist[] = {"ifname", "gateway", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sz",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszIPv6Gateway))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_ipv6_gateway(self->hHandle,
                                             pszInterfaceName,
                                             pszIPv6Gateway);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_ipv6_gateway(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    char *pszIPv6Gateway = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s",
                                     kwlist,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_ipv6_gateway(self->hHandle,
                                             pszInterfaceName,
                                             &pszIPv6Gateway);
    BAIL_ON_PMD_ERROR(dwError);

    pyRes = Py_BuildValue("s", pszIPv6Gateway);

cleanup:
    PMDFreeMemory(pszIPv6Gateway);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
add_dns_server(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char *pszServer = NULL;
    static char *kwlist[] = {"server", "ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s|s",
                                     kwlist,
                                     &pszServer,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_add_dns_server(self->hHandle,
                                           pszInterfaceName,
                                           pszServer);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
delete_dns_server(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char *pszServer = NULL;
    static char *kwlist[] = {"server", "ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s|s",
                                     kwlist,
                                     &pszServer,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_delete_dns_server(self->hHandle,
                                              pszInterfaceName,
                                              pszServer);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_dns_servers(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    int dnsMode = DNS_MODE_MAX;
    char *pszMode = NULL;
    char *pszInterfaceName = NULL;
    char **ppszServersList = NULL;
    PyObject *pServerList = Py_None;
    static char *kwlist[] = {"dns_mode", "servers", "ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s|O|s",
                                     kwlist,
                                     &pszMode,
                                     &pServerList,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if (!strcmp(pszMode, "dhcp"))
    {
        dnsMode = DHCP_DNS;
    }
    else if (!strcmp(pszMode, "static"))
    {
        dnsMode = STATIC_DNS;
    }
    else
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if ((pServerList != Py_None) && (PyList_Size(pServerList) > 0))
    {
        dwError = py_list_as_string_list(pServerList,
                                         &ppszServersList,
                                         &count);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_dns_servers(self->hHandle,
                                            pszInterfaceName,
                                            dnsMode,
                                            count,
                                            ppszServersList);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(ppszServersList, count);
    pyRes = Py_BuildValue("i", dwError);
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
    NET_DNS_MODE dnsMode = DNS_MODE_UNKNOWN;
    char *pszInterfaceName = NULL;
    char *pszDnsMode = NULL;
    char **ppszDnsServers = NULL;
    PyObject *pPyDnsServersList = Py_None;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if(!PyArg_ParseTupleAndKeywords(arg, kwds, "|s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_dns_servers(self->hHandle,
                                            pszInterfaceName,
                                            &dnsMode,
                                            &count,
                                            &ppszDnsServers);
    BAIL_ON_PMD_ERROR(dwError);

    pPyDnsServersList = PyList_New(0);
    for (i = 0; i < count; i++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszDnsServers[i]);
        if (PyList_Append(pPyDnsServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    if (dnsMode == DNS_MODE_UNKNOWN)
    {
        pszDnsMode = "invalid";
    }
    else if (dnsMode == STATIC_DNS)
    {
        pszDnsMode = "static";
    }
    else
    {
        pszDnsMode = "dhcp";
    }

    pyRes = PyTuple_New(2);
    PyTuple_SetItem(pyRes, 0, Py_BuildValue("s", pszDnsMode));
    PyTuple_SetItem(pyRes, 1, pPyDnsServersList);

cleanup:
    PMDFreeStringArrayWithCount(ppszDnsServers, count);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_dns_domains(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char **ppszDomainsList = NULL;
    PyObject *pDomainList = Py_None;
    static char *kwlist[] = {"domains", "ifname", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "O|s",
                                     kwlist,
                                     &pDomainList,
                                     &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    if ((pDomainList != Py_None) && (PyList_Size(pDomainList) > 0))
    {
        dwError = py_list_as_string_list(pDomainList,
                                         &ppszDomainsList,
                                         &count);
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_dns_domains(self->hHandle,
                                            pszInterfaceName,
                                            count,
                                            ppszDomainsList);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(ppszDomainsList, count);
    pyRes = Py_BuildValue("i", dwError);
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
    char *pszInterfaceName = NULL;
    char **ppszDnsDomains = NULL;
    PyObject *pPyDnsDomainsList = Py_None;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pyRes = Py_None;

    if(!PyArg_ParseTupleAndKeywords(arg, kwds, "|s", kwlist, &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_dns_domains(self->hHandle,
                                            pszInterfaceName,
                                            &count,
                                            &ppszDnsDomains);
    if (dwError == NM_ERR_VALUE_NOT_FOUND)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    pPyDnsDomainsList = PyList_New(0);
    for (i = 0; i < count; i++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszDnsDomains[i]);
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
set_ntp_servers(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char **ppszNtpServersList = NULL;
    PyObject *pNtpServerList = Py_None;
    static char *kwlist[] = {"ntpservers", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "O",
                                     kwlist,
                                     &pNtpServerList))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = py_list_as_string_list(pNtpServerList,
                                     &ppszNtpServersList,
                                     &count);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_set_ntp_servers(self->hHandle,
                                            count,
                                            ppszNtpServersList);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(ppszNtpServersList, count);
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
add_ntp_servers(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char **ppszNtpServersList = NULL;
    PyObject *pNtpServerList = Py_None;
    static char *kwlist[] = {"ntpservers", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "O",
                                     kwlist,
                                     &pNtpServerList))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = py_list_as_string_list(pNtpServerList,
                                     &ppszNtpServersList,
                                     &count);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_add_ntp_servers(self->hHandle,
                                            count,
                                            (const char **)ppszNtpServersList);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(ppszNtpServersList, count);
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
delete_ntp_servers(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    size_t i = 0, count = 0;
    char *pszInterfaceName = NULL;
    char **ppszNtpServersList = NULL;
    PyObject *pNtpServerList = Py_None;
    static char *kwlist[] = {"ntpservers", NULL};
    PyObject *pyRes = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "O",
                                     kwlist,
                                     &pNtpServerList))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = py_list_as_string_list(pNtpServerList,
                                     &ppszNtpServersList,
                                     &count);
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_delete_ntp_servers(self->hHandle,
                                               count,
                                               (const char **)ppszNtpServersList);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(ppszNtpServersList, count);
    pyRes = Py_BuildValue("i", dwError);
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
    char **ppszNtpServers = NULL;
    PyObject *pPyNtpServersList = Py_None;
    PyObject *pyRes = Py_None;

    dwError = netmgr_client_get_ntp_servers(self->hHandle,
                                            &count,
                                            &ppszNtpServers);
    if (dwError == NM_ERR_VALUE_NOT_FOUND)
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    pPyNtpServersList = PyList_New(0);
    for (i = 0; i < count; i++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszNtpServers[i]);
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
add_static_ip_route(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, metric = 0, table = 0;
    char *pszInterfaceName = NULL;
    char *pszDestNetwork = NULL;
    char *pszSourceNetwork = NULL;
    char *pszGateway = NULL;
    NET_ROUTE_SCOPE scope = GLOBAL_ROUTE;
    NET_IP_ROUTE pIpRoute = {0};
    PyObject *pyRes = Py_None;
    static char *kwlist[] = {"ifname",
                             "destination",
                             "gateway",
                             "metric",
                             "source",
                             "scope",
                             "table",
                             NULL};

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sss|i|s|i|i",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszDestNetwork,
                                     &pszGateway,
                                     &metric,
                                     &pszSourceNetwork,
                                     &scope,
                                     &table))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pIpRoute.pszInterfaceName = pszInterfaceName;
    pIpRoute.pszDestNetwork = pszDestNetwork;
    pIpRoute.pszGateway = pszGateway;
    pIpRoute.metric = metric;
    pIpRoute.pszSourceNetwork = pszSourceNetwork;
    pIpRoute.scope = scope;
    pIpRoute.table = table;

    dwError = netmgr_client_add_static_ip_route(self->hHandle, &pIpRoute);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
delete_static_ip_route(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, metric = 0, table = 0;
    char *pszInterfaceName = NULL;
    char *pszDestNetwork = NULL;
    char *pszSourceNetwork = NULL;
    char *pszGateway = NULL;
    NET_ROUTE_SCOPE scope = GLOBAL_ROUTE;
    NET_IP_ROUTE pIpRoute = {0};
    PyObject *pyRes = Py_None;
    static char *kwlist[] = {"ifname",
                             "destination",
                             "gateway",
                             "metric",
                             "source",
                             "scope",
                             "table",
                             NULL};

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss|s|i|s|i|i",
                                     kwlist,
                                     &pszInterfaceName,
                                     &pszDestNetwork,
                                     &pszGateway,
                                     &metric,
                                     &pszSourceNetwork,
                                     &scope,
                                     &table))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pIpRoute.pszInterfaceName = pszInterfaceName;
    pIpRoute.pszDestNetwork = pszDestNetwork;
    pIpRoute.pszSourceNetwork = pszSourceNetwork;
    pIpRoute.pszGateway = pszGateway;
    pIpRoute.scope = scope;
    pIpRoute.metric = metric;
    pIpRoute.table = table;

    dwError = netmgr_client_delete_static_ip_route(self->hHandle, &pIpRoute);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pyRes = Py_BuildValue("i", dwError);
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}


static uint32_t
fill_route_info(
    PPY_NET self,
    NET_IP_ROUTE *pNetRouteInfo,
    PPY_IP_ROUTE *ppPyIpRoute
)
{
    uint32_t dwError = 0;
    PyTypeObject *retType = &routeType;
    PPY_IP_ROUTE pPyRouteObject = NULL;

    if (!pNetRouteInfo|| !ppPyIpRoute)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRouteObject = (PPY_IP_ROUTE)retType->tp_alloc(retType, 0);
    if (!pPyRouteObject)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyRouteObject->pRouteDestNetwork = Py_BuildValue("s",
                                                pNetRouteInfo->pszDestNetwork);
    pPyRouteObject->pRouteSourceNetwork = Py_BuildValue("s",
                                              pNetRouteInfo->pszSourceNetwork);
    pPyRouteObject->pRouteGateway = Py_BuildValue("s",
                                                  pNetRouteInfo->pszGateway);
    pPyRouteObject->scope = pNetRouteInfo->scope;
    pPyRouteObject->metric = pNetRouteInfo->metric;
    pPyRouteObject->table = pNetRouteInfo->table;

    *ppPyIpRoute = pPyRouteObject;

cleanup:
    return dwError;
error:
    Py_XDECREF((PyObject *)pPyRouteObject);
    goto cleanup;
}

static uint32_t
fill_link_info(
    PPY_NET self,
    NET_LINK_INFO *pNetLinkInfo,
    PPY_LINK *pppyLinkObject
)
{
    uint32_t dwError = 0, linkMtu = 0, ndhcpEnabled = 0, nautoconfEnabled = 0;
    uint32_t dwIaid = 0;
    size_t countDnsServers = 0, countDnsDomains = 0, countRoutes = 0;
    size_t countIpv6List = 0;
    size_t i = 0, j = 0;
    NET_LINK_MODE linkMode = LINK_MODE_UNKNOWN;
    NET_LINK_STATE linkState = LINK_STATE_UNKNOWN;
    NET_DNS_MODE dnsMode = DNS_MODE_UNKNOWN;
    NET_IPV4_ADDR_MODE addrMode = IPV4_ADDR_MODE_NONE;
    char *pszDuid = 0, *pszIfName = NULL, *pszAddrMode = NULL;
    char *pszMacAddress = NULL, *pszIpv4Addr =NULL, *pszDnsMode = NULL;
    char *pszIpv4Gateway = NULL, *pszIpv6Gateway = NULL;
    char **ppszDnsServers = NULL, **ppszDnsDomains = NULL;
    PyTypeObject *retType = &linkType;
    PPY_LINK pPyLinkObject = NULL;
    NET_IP_ROUTE **ppRouteList = NULL;
    NET_IP_ADDR **ppipaddrList = NULL;
    PyObject *pPyDnsServersList = PyList_New(0);
    PyObject *pPyDnsDomainsList = PyList_New(0);
    PyObject *pPyIpv6AddrList = PyList_New(0);
    PyObject *pyIpRoutesList = PyList_New(0);

    if (!pNetLinkInfo || !pppyLinkObject)
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pPyLinkObject = (PPY_LINK)retType->tp_alloc(retType, 0);
    if (!pPyLinkObject)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pszIfName = pNetLinkInfo->pszInterfaceName;

    pszMacAddress = pNetLinkInfo->pszMacAddress;

    linkMode = pNetLinkInfo->mode;

    linkMtu = pNetLinkInfo->mtu;

    linkState = pNetLinkInfo->state;

    dwError = netmgr_client_get_duid(self->hHandle, pszIfName, &pszDuid);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv4_addr_gateway(self->hHandle,
                                                  pszIfName,
                                                  &addrMode,
                                                  &pszIpv4Addr,
                                                  &pszIpv4Gateway);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    if (addrMode == IPV4_ADDR_MODE_NONE)
    {
        pszAddrMode = "none";
    }
    else if (addrMode == IPV4_ADDR_MODE_DHCP)
    {
        pszAddrMode = "dhcp";
    }
    else
    {
        pszAddrMode = "static";
    }

    dwError = netmgr_client_get_ipv6_addr_mode(self->hHandle,
                                               pszIfName,
                                               &ndhcpEnabled,
                                               &nautoconfEnabled);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_ipv6_gateway(self->hHandle,
                                             pszIfName,
                                             &pszIpv6Gateway);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    dwError = netmgr_client_get_dns_servers(self->hHandle,
                                            pszIfName,
                                            &dnsMode,
                                            &countDnsServers,
                                            &ppszDnsServers);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    if (dnsMode == DNS_MODE_UNKNOWN)
    {
        pszDnsMode = "invalid";
    }
    else if (dnsMode == STATIC_DNS)
    {
        pszDnsMode = "static";
    }
    else
    {
        pszDnsMode = "dhcp";
    }

    for (j = 0; j < countDnsServers; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszDnsServers[j]);
        if (PyList_Append(pPyDnsServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_dns_domains(self->hHandle,
                                            pszIfName,
                                            &countDnsDomains,
                                            &ppszDnsDomains);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    for (j = 0; j < countDnsDomains; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszDnsDomains[j]);
        if (PyList_Append(pPyDnsDomainsList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_ip_addr(self->hHandle,
                                        pszIfName,
                                        DHCP_IPV6 | AUTO_IPV6 | STATIC_IPV6,
                                        &countIpv6List,
                                        &ppipaddrList);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    for (j = 0; j < countIpv6List; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppipaddrList[j]->pszIPAddrPrefix);
        if (PyList_Append(pPyIpv6AddrList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_static_ip_routes(self->hHandle,
                                                 pszIfName,
                                                 &countRoutes,
                                                 &ppRouteList);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    for (j = 0; j < countRoutes; j++)
    {
        PPY_IP_ROUTE ipRoute = NULL;

        dwError = fill_route_info(self, ppRouteList[j], &ipRoute);
        BAIL_ON_PMD_ERROR(dwError);

        if (PyList_Append(pyIpRoutesList, (PyObject *)ipRoute) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_iaid(self->hHandle,
                                     pszIfName,
                                     &dwIaid);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    pPyLinkObject->pInterface_name = Py_BuildValue("s", pszIfName);
    pPyLinkObject->pDuid = Py_BuildValue("s", pszDuid);
    pPyLinkObject->pIaid = Py_BuildValue("i", dwIaid);
    pPyLinkObject->pMacAddress = Py_BuildValue("s", pszMacAddress);
    pPyLinkObject->pLinkMode = Py_BuildValue("s",
                                             py_link_mode_to_string(linkMode));
    pPyLinkObject->link_mtu = linkMtu;
    pPyLinkObject->pLinkState = Py_BuildValue("s",
                                              py_link_state_to_string(linkState));
    pPyLinkObject->pIpv4AddrMode = Py_BuildValue("s", pszAddrMode);
    pPyLinkObject->pIpv4_addr = Py_BuildValue("s", pszIpv4Addr);
    pPyLinkObject->pIpv4_gateway = Py_BuildValue("s", pszIpv4Gateway);
    pPyLinkObject->ipv6_dhcp_enabled = ndhcpEnabled ? Py_True : Py_False;
    pPyLinkObject->ipv6_autoconf_enabled = nautoconfEnabled ? Py_True :
                                            Py_False;
    pPyLinkObject->pIpv6_gateway = Py_BuildValue("s", pszIpv6Gateway);
    pPyLinkObject->pIpv6_addr_list = (PyObject *)pPyIpv6AddrList;
    pPyLinkObject->pDnsMode = Py_BuildValue("s", pszDnsMode);
    pPyLinkObject->pServersList = (PyObject *)pPyDnsServersList;
    pPyLinkObject->pDomainsList = (PyObject *)pPyDnsDomainsList;
    pPyLinkObject->pIP_Route_Info = (PyObject *)pyIpRoutesList;

    *pppyLinkObject = pPyLinkObject;

cleanup:
    PMDFreeMemory(pszDuid);
    PMDFreeMemory(pszIpv4Addr);
    PMDFreeMemory(pszIpv4Gateway);
    PMDFreeMemory(pszIpv6Gateway);
    PMDFreeStringArrayWithCount(ppszDnsServers, countDnsServers);
    PMDFreeStringArrayWithCount(ppszDnsDomains, countDnsDomains);
    if (ppRouteList)
    {
        for (j= 0; j < countRoutes; j++)
        {
            PMDFreeMemory(ppRouteList[j]->pszInterfaceName);
            PMDFreeMemory(ppRouteList[j]->pszDestNetwork);
            PMDFreeMemory(ppRouteList[j]->pszSourceNetwork);
            PMDFreeMemory(ppRouteList[j]->pszGateway);
            PMDFreeMemory(ppRouteList[j]);
        }
        PMDFreeMemory(ppRouteList);
    }
    if (ppipaddrList)
    {
        for (j = 0; j < countIpv6List; j++)
        {
            PMDFreeMemory(ppipaddrList[j]->pszInterfaceName);
            PMDFreeMemory(ppipaddrList[j]->pszIPAddrPrefix);
            PMDFreeMemory(ppipaddrList[j]);
        }
        PMDFreeMemory(ppipaddrList);
    }
    return dwError;
error:
    Py_XDECREF((PyObject *)pPyLinkObject);
    goto cleanup;
}

static PyObject *
get_link_info(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    static char *kwlist[] = {"ifname", NULL};
    PyObject *pPyLinkDict = Py_None;
    NET_LINK_INFO *pLinkInfo = NULL, *pCur = NULL;
    PyObject *pyRes = Py_None;

    if(!PyArg_ParseTupleAndKeywords(arg,
                                kwds,
                                "|s",
                                kwlist,
                                &pszInterfaceName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_link_info(self->hHandle,
                                          pszInterfaceName,
                                          &pLinkInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pPyLinkDict = PyDict_New();
    for (pCur = pLinkInfo; pCur; pCur = pCur->pNext)
    {
        PPY_LINK pPyLinkObject = NULL;

        dwError = fill_link_info(self, pCur, &pPyLinkObject);
        BAIL_ON_PMD_ERROR(dwError);

        if (PyDict_SetItem(pPyLinkDict, pPyLinkObject->pInterface_name,
            (PyObject *)pPyLinkObject) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }
    pyRes = pPyLinkDict;

cleanup:
    while (pLinkInfo)
    {
        pCur = pLinkInfo;
        pLinkInfo = pLinkInfo->pNext;
        PMDFreeMemory(pCur->pszInterfaceName);
        PMDFreeMemory(pCur->pszMacAddress);
        PMDFreeMemory(pCur);
    }
    return pyRes;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_system_network_info(
    PPY_NET self,
    PyObject *arg
    )
{
    uint32_t dwError = 0;
    size_t j = 0;
    size_t countDnsServers = 0, countDnsDomains = 0, countNtpServers = 0;
    NET_DNS_MODE dnsMode = DNS_MODE_UNKNOWN;
    PPY_SYSTEM pPySystemObject = NULL;
    char *pszDuid = 0, *pszDnsMode = NULL;
    char **ppszDnsServers = NULL, **ppszDnsDomains = NULL;
    char **ppszNtpServers = NULL;
    PyTypeObject *retType = &systemType;
    PyObject *pPySystemInfoList = Py_None;
    PyObject *pPyDnsServersList = Py_None;
    PyObject *pPyDnsDomainsList = Py_None;
    PyObject *pPyNtpServersList = Py_None;
    PyObject *pyRes = Py_None;

    pPySystemObject = (PPY_SYSTEM)retType->tp_alloc(retType, 0);
    if (!pPySystemObject)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }
    dwError = netmgr_client_get_dns_servers(self->hHandle,
                                            NULL,
                                            &dnsMode,
                                            &countDnsServers,
                                            &ppszDnsServers);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    if (dnsMode == DNS_MODE_UNKNOWN)
    {
        pszDnsMode = "invalid";
    }
    else if (dnsMode == STATIC_DNS)
    {
        pszDnsMode = "static";
    }
    else 
    {
        pszDnsMode = "dhcp";
    }

    pPySystemInfoList = PyList_New(0);
    pPyDnsServersList = PyList_New(0);
    for (j = 0; j < countDnsServers; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszDnsServers[j]);
        if (PyList_Append(pPyDnsServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_dns_domains(self->hHandle,
                                            NULL,
                                            &countDnsDomains,
                                            &ppszDnsDomains);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    pPyDnsDomainsList = PyList_New(0);
    for (j = 0; j < countDnsDomains; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszDnsDomains[j]);
        if (PyList_Append(pPyDnsDomainsList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_ntp_servers(self->hHandle,
                                            &countNtpServers,
                                            &ppszNtpServers);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    pPyNtpServersList = PyList_New(0);
    for (j = 0; j < countNtpServers; j++)
    {
        PyObject *ptoAppend = Py_BuildValue("s", ppszNtpServers[j]);
        if (PyList_Append(pPyNtpServersList, ptoAppend) == -1)
        {
            dwError = ERROR_PMD_OUT_OF_MEMORY;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_get_duid(self->hHandle, NULL, &pszDuid);
    if ((dwError == NM_ERR_VALUE_NOT_FOUND) || (dwError == ENOENT))
    {
        dwError = 0;
    }
    BAIL_ON_PMD_ERROR(dwError);

    pPySystemObject->pDnsMode = Py_BuildValue("s", pszDnsMode);
    pPySystemObject->pServersList = (PyObject *)pPyDnsServersList;
    pPySystemObject->pDomainsList = (PyObject *)pPyDnsDomainsList;
    pPySystemObject->pNtpServersList = (PyObject *)pPyNtpServersList;
    pPySystemObject->pDuid = Py_BuildValue("s", pszDuid);

    if (PyList_Append(pPySystemInfoList, (PyObject *)pPySystemObject) == -1)
    {
        dwError = ERROR_PMD_OUT_OF_MEMORY;
        BAIL_ON_PMD_ERROR(dwError);
    }

    pyRes = pPySystemInfoList;

cleanup:
    PMDFreeMemory(pszDuid);
    PMDFreeStringArrayWithCount(ppszDnsServers, countDnsServers);
    PMDFreeStringArrayWithCount(ppszDnsDomains, countDnsDomains);
    PMDFreeStringArrayWithCount(ppszNtpServers, countNtpServers);
    return pyRes;

error:
    Py_XDECREF(pPySystemObject);
    pPyDnsServersList = Py_None;
    pPyDnsDomainsList = Py_None;
    pPySystemInfoList = Py_None;
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
net_py_getfirewall(
    PPY_NET self,
    void *closure)
{
    return NULL;
#if 0
    uint32_t dwError = 0;
    PyTypeObject *retType = &firewallType;
    PPY_NM_FIREWALL pyFirewall = NULL;

    if(!self->firewall)
    {
        self->firewall = retType->tp_alloc(retType, 0);
        if(!self->firewall)
        {
            dwError = ENOMEM;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    pyFirewall = (PPY_NM_FIREWALL)self->firewall;
    pyFirewall->pNet = (PyObject *)self;

cleanup:
    return self->firewall;
error:
    self->firewall = Py_None;
    goto cleanup;
#endif
}

static PyObject *
wait_for_link_up(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0;
    char *pszInterfaceName = NULL;
    uint32_t dwTimeout = 0;
    static char *kwlist[] = {"ifname", "timeout", NULL};
    PyObject *pResult = Py_None;
    NET_LINK_INFO *pLinkInfo = NULL, *pCur = NULL;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "si",
                                     kwlist,
                                     &pszInterfaceName,
                                     &dwTimeout))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_wait_for_link_up(self->hHandle,
                                          pszInterfaceName,
                                          dwTimeout);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pResult = Py_BuildValue("i", dwError);
    return pResult;

error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

typedef struct _NM_CLI_ADDR_STR_TYPE
{
    char *pszIpAddrType;
    NET_ADDR_TYPE ipAddrType;
} NM_CLI_ADDR_STR_TYPE, *PNM_CLI_ADDR_STR_TYPE;

NM_CLI_ADDR_STR_TYPE addrStrToTypeMap[] =
{
    { "ipv4",               NET_ADDR_IPV4       },
    { "ipv6",               NET_ADDR_IPV6       },
    { "static_ipv4",        STATIC_IPV4         },
    { "static_ipv6",        STATIC_IPV6         },
    { "dhcp_ipv4",          DHCP_IPV4           },
    { "dhcp_ipv6",          DHCP_IPV6           },
    { "auto_ipv6",          AUTO_IPV6           },
    { "link_local_ipv6",    LINK_LOCAL_IPV6     },
};

static PyObject *
wait_for_ip(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, dwTimeout = 0;
    size_t i = 0, j = 0, count = 0, addrTypeCount = 0;
    char *pszInterfaceName = NULL;
    char *s1 = NULL, *s2 = NULL;
    char **ppszAddrTypeList = NULL;
    NET_ADDR_TYPE dwAddrTypes = 0;
    PyObject *pPyResult = Py_None;
    PyObject *pszAddrTypes = Py_None;
    static char *kwlist[] = {"ifname", "timeout", "addrtype", NULL};

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "sdO",
                                     kwlist,
                                     &pszInterfaceName,
                                     &dwTimeout,
                                     &pszAddrTypes))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = py_list_as_string_list(pszAddrTypes,
                                     &ppszAddrTypeList,
                                     &count);
    BAIL_ON_PMD_ERROR(dwError);

    addrTypeCount = sizeof(addrStrToTypeMap)/sizeof(NM_CLI_ADDR_STR_TYPE);

    for (i = 0; i < count; i++)
    {
        for (j = 0; j < addrTypeCount; j++)
        {
            if (!strcmp(ppszAddrTypeList[i], addrStrToTypeMap[j].pszIpAddrType))
            {
                dwAddrTypes |= addrStrToTypeMap[j].ipAddrType;
                break;
            }
        }
        if (j == addrTypeCount)
        { 
            dwError = ERROR_PMD_INVALID_PARAMETER;
            BAIL_ON_PMD_ERROR(dwError);
        }
    }

    dwError = netmgr_client_wait_for_ip(self->hHandle,
                                        pszInterfaceName,
                                        dwTimeout,
                                        dwAddrTypes);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeStringArrayWithCount(ppszAddrTypeList, count);
    pPyResult = Py_BuildValue("i", dwError);
    return pPyResult;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_err_info(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, error = 0;
    static char *kwlist[] = {"error", NULL};
    char *pszErrorInfo = NULL;
    PyObject *pPyResult = Py_None;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "l",
                                     kwlist,
                                     &error))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_error_info(self->hHandle,
                                           error,
                                           &pszErrorInfo);
    BAIL_ON_PMD_ERROR(dwError);

    pPyResult = Py_BuildValue("s", pszErrorInfo);

cleanup:
    PMDFreeMemory(pszErrorInfo);
    return pPyResult;
error:
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

static PyObject *
set_hostname(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, error = 0;
    static char *kwlist[] = {"hostname", NULL};
    char *pszErrorInfo = NULL;
    PyObject *pPyResult = Py_None;
    char *pszHostname = NULL;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "s",
                                     kwlist,
                                     &pszHostname))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_hostname(self->hHandle,
                                         pszHostname);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    PMDFreeMemory(pszErrorInfo);
    pPyResult = Py_BuildValue("i", dwError);
    return pPyResult;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
get_network_param(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, error = 0;
    static char *kwlist[] = {"object", "paramname", NULL};
    PyObject *pPyResult = Py_None;
    char *pszObjectName = NULL, *pszParamName = NULL, *pszParamValue = NULL;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss",
                                     kwlist,
                                     &pszObjectName,
                                     &pszParamName))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_get_network_param(self->hHandle,
                                              pszObjectName,
                                              pszParamName,
                                              &pszParamValue);
    BAIL_ON_PMD_ERROR(dwError);

    pPyResult = Py_BuildValue("s", pszParamValue);

cleanup:
    PMDFreeMemory(pszParamValue);
    return pPyResult;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}

static PyObject *
set_network_param(
    PPY_NET self,
    PyObject *arg,
    PyObject *kwds
    )
{
    uint32_t dwError = 0, error = 0;
    static char *kwlist[] = {"object", "paramname", "paramvalue",  NULL};
    PyObject *pPyResult = Py_None;
    char *pszObjectName = NULL, *pszParamName = NULL, *pszParamValue = NULL;

    if (!PyArg_ParseTupleAndKeywords(arg,
                                     kwds,
                                     "ss|z",
                                     kwlist,
                                     &pszObjectName,
                                     &pszParamName,
                                     &pszParamValue))
    {
        dwError = ERROR_PMD_INVALID_PARAMETER;
        BAIL_ON_PMD_ERROR(dwError);
    }

    dwError = netmgr_client_set_network_param(self->hHandle,
                                              pszObjectName,
                                              pszParamName,
                                              pszParamValue);
    BAIL_ON_PMD_ERROR(dwError);

cleanup:
    pPyResult = Py_BuildValue("i", dwError);
    return pPyResult;
error:
    raise_netmgr_exception(self, dwError);
    goto cleanup;
}


static PyMethodDef net_methods[] =
{
    {"set_dhcp_duid", (PyCFunction)set_dhcp_duid, METH_VARARGS|METH_KEYWORDS,
     "net.set_dhcp_duid(duid = \"11:22:33:44:55:66:77:20\", ifname = interfacename) \n\
     set dhcp duid (interface optional). returns 0 if successful, exception on failure.\n"},
    {"get_dhcp_duid", (PyCFunction)get_dhcp_duid, METH_VARARGS|METH_KEYWORDS,
     "net.get_dhcp_duid(ifname = interface)\n\
     get dhcp duid (interface optional). returns DUID if successful, exception on failure.\n"},
    {"set_link_iaid", (PyCFunction)set_link_iaid, METH_VARARGS|METH_KEYWORDS,
     "net.set_link_iaid(ifname = interfacename, iaid = 1234) \n\
     set interface iaid. returns 0 if successful, exception on failure.\n"},
    {"get_link_iaid", (PyCFunction)get_link_iaid, METH_VARARGS|METH_KEYWORDS,
     "net.get_link_iaid(ifname = interface)\n\
     get interface iaid. returns IAID if successful, exception on failure.\n"},
    {"set_link_macaddr", (PyCFunction)set_link_macaddr,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_link_macaddr(ifname = interfacename, macaddr = \"10:20:30:40:50:60\") \n\
     sets macaddress. returns 0 if successful, exception on failure.\n"},
    {"get_link_macaddr", (PyCFunction)get_link_macaddr,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_macaddr(ifname = interfacename\") \n\
     gets macaddress. returns MAC address if successful, exception on failure.\n"},
    {"set_link_mtu", (PyCFunction)set_link_mtu, METH_VARARGS|METH_KEYWORDS,
     "net.set_link_mtu(ifname = interfacename, mtu = 1500) \n\
     sets mtu of interface. returns 0 if successful, exception on failure.\n"},
    {"get_link_mtu", (PyCFunction)get_link_mtu,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_mtu(ifname = interfacename\") \n\
     gets link mtu. returns link MTU if successful, exception on failure.\n"},
    {"set_link_mode", (PyCFunction)set_link_mode, METH_VARARGS|METH_KEYWORDS,
     "net.set_link_mode(ifname = interfacename, "
     "link_mode = [aut0, manual])\n\
     sets mode of interface. returns 0 if successful, exception on failure.\n"},
    {"get_link_mode", (PyCFunction)get_link_mode,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_mode(ifname = interfacename\") \n\
     gets link mode. returns link mode if successful, exception on failure.\n"},
    {"set_link_state", (PyCFunction)set_link_state, METH_VARARGS|METH_KEYWORDS,
     "net.set_link_state(ifname = interfacename, "
     "link_state = [down, up]) \n\
     sets state of interface. returns 0 if successful, exception on failure.\n"},
    {"get_link_state", (PyCFunction)get_link_state,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_link_state(ifname = interfacename\") \n\
     gets link state. returns link state if successful, exception on failure.\n"},
    {"set_link_up", (PyCFunction)set_link_up, METH_VARARGS|METH_KEYWORDS,
     "net.set_link_up(ifname = interfacename) \n\
     brings interface up. returns 0 if successful, exception on failure.\n"},
    {"set_link_down", (PyCFunction)set_link_down, METH_VARARGS|METH_KEYWORDS,
     "net.set_link_down(ifname = interfacename) \n\
     brings interface down. returns 0 if successful, exception on failure.\n"},
    {"set_ipv4_addr_gateway", (PyCFunction)set_ipv4_addr_gateway,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_ipv4_addr_gateway(ifname = interfacename, addr_mode = [dhcp, static, none], "
     "addr_prefix = ipv4addressprefix, gateway = ipv4gateway) \n\
     set ipv4 address with prefix and gateway for the interface."
     "returns 0 if successful, exception on failure.\n"},
    {"get_ipv4_addr_gateway", (PyCFunction)get_ipv4_addr_gateway,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_ipv4_addr_gateway(ifname = interfacename) \n\
     get ipv4 address with prefix and gateway for the interface."
     "returns IPv4 addr & gateway if successful, exception on failure.\n"},
    {"add_static_ipv6_addr", (PyCFunction)add_static_ipv6_addr,
     METH_VARARGS|METH_KEYWORDS,
     "net.add_static_ipv6_addr(ifname = interfacename, "
     "addr_prefix = ipv6addressprefix) \n\
     adds static ipv6 address for the interface. returns 0 if successful, exception on failure.\n"},
    {"del_static_ipv6_addr", (PyCFunction)delete_static_ipv6_addr,
     METH_VARARGS|METH_KEYWORDS,
     "net.del_static_ipv6_addr(ifname = interfacename, "
     "addr_prefix = ipv6addressprefix) \n\
     delete static ipv6 address assigned to the interface. returns 0 if"
     " successful, exception on failure.\n"},
    {"get_ipv6_addr", (PyCFunction)get_ipv6_addr,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_ipv6_addr(ifname = interfacename) \n\
     get the list of IPv6 addresses for the interface. "
     "returns IPv6 address list if successful, exception on failure.\n"},
    {"set_ipv6_addr_mode", (PyCFunction)set_ipv6_addr_mode,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_ipv6_addr_mode(ifname = interfacename, "
     "enable_dhcp = [True, False], enable_autoconf = [True, False]) \n\
     enable dhcp and autoconf for the ipv6 address. "
     "returns 0 if successful, exception on failure.\n"},
    {"get_ipv6_addr_mode", (PyCFunction)get_ipv6_addr_mode,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_ipv6_addr_mode(ifname = interfacename) \n\
     returns if dhcpv6, autoconfv6 are enabled or disabled. "
     "returns dhcpv6 & autoconf settings if successful, exception on failure.\n"},
    {"set_ipv6_gateway", (PyCFunction)set_ipv6_gateway,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_ipv6_gateway(ifname = interfacename, gateway = ipv6gateway) \n\
     set the IPv6 gateway for the interface. "
     "returns 0 if successful, exception on failure.\n"},
    {"get_ipv6_gateway", (PyCFunction)get_ipv6_gateway,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_ipv6_gateway(ifname = interfacename) \n\
     get the IPv6 gateway for the interface. "
     "returns IPv6 gateway if successful, exception on failure.\n"},
    {"add_dns_server", (PyCFunction)add_dns_server,
     METH_VARARGS|METH_KEYWORDS,
     "net.add_dns_server(server = \"10.20.30.40\", ifname = interfacename) \n\
     add dns server. returns 0 if successful, exception on failure.\n"},
    {"delete_dns_server", (PyCFunction)delete_dns_server,
     METH_VARARGS|METH_KEYWORDS,
     "net.delete_dns_servers(server = \"10.20.30.40\", ifname = interfacename) \n\
     delete dns server. returns 0 if successful, exception on failure.\n"},
    {"set_dns_servers", (PyCFunction)set_dns_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_dns_servers(dns_mode = [dhcp, static], "
     "servers = [\"10.20.30.40\",\"20.20.20.20\"], ifname = interfacename) \n\
     set dns servers and the mode. returns 0 if successful, exception on failure.\n"},
    {"get_dns_servers", (PyCFunction)get_dns_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_dns_servers(ifname = interfacename) \n\
     get dns servers and the mode. returns dns servers, mode if successful, exception on failure.\n"},
    {"set_dns_domains", (PyCFunction)set_dns_domains,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_dns_domains(domains = [\"abcd.com\"], ifname = interfacename) \n\
     set dns domains. returns 0 if successful, exception on failure.\n"},
    {"get_dns_domains", (PyCFunction)get_dns_domains,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_dns_domains(ifname = interfacename) \n\
     get dns domains. returns dns domains if successful, exception on failure.\n"},
    {"set_ntp_servers", (PyCFunction)set_ntp_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.set_ntp_servers(ntpservers = [\"20.20.20.20\", \"25.30.40.70\"]) \n\
     set ntp servers. returns 0 if successful, exception on failure.\n"},
    {"add_ntp_servers", (PyCFunction)add_ntp_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.add_ntp_servers(ntpservers = [\"20.20.20.20\", \"25.30.40.70\"]) \n\
     adds ntp servers. returns 0 if successful, exception on failure.\n"},
    {"del_ntp_servers", (PyCFunction)delete_ntp_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.del_ntp_servers(ntpservers = [\"20.20.20.20\", \"25.30.40.70\"]) \n\
     deletes ntp servers. returns 0 if successful, exception on failure.\n"},
    {"get_ntp_servers", (PyCFunction)get_ntp_servers,
     METH_VARARGS|METH_KEYWORDS,
     "net.get_ntp_servers() \n\
     get ntp servers. returns NTP servers list if successful, exception on failure.\n"},
    {"add_static_ip_route", (PyCFunction)add_static_ip_route,
     METH_VARARGS|METH_KEYWORDS,
     "net.add_static_ip_route(ifname = interfacename, "
     "destination = destination network, "
     "source = source network, gateway = gateway_address, "
     "scope = 1, metric = 10, table = 0) \n\
     adds a static route to the interface. returns 0 if successful, exception on failure.\n"},
    {"delete_static_ip_route", (PyCFunction)delete_static_ip_route,
     METH_VARARGS|METH_KEYWORDS,
     "net.delete_static_ip_route(ifname = interfacename, "
     "destination = destination network, source = source network, "
     "gateway = gateway, scope = 0, metric = 1, table = 100) \n\
     deletes a static route to the interface. returns 0 if successful, exception on failure.\n"},
    {"get_link_info", (PyCFunction)get_link_info, METH_VARARGS|METH_KEYWORDS,
     "net.get_link_info(ifname = interfacename)\n\
     get link info per interface or all interface.\n"},
    {"get_system_network_info", (PyCFunction)get_system_network_info,
     METH_NOARGS, "net.get_system_network_info()\n\
     get network info common to the entire system.\n"},
    {"wait_for_link_up", (PyCFunction)wait_for_link_up,
     METH_VARARGS|METH_KEYWORDS, "net.wait_for_link_up(ifname = interfacename, "
     "timeout = timeout)\n\
     wait for link up.\n"},
    {"wait_for_ip", (PyCFunction)wait_for_ip,
     METH_VARARGS|METH_KEYWORDS, "net.wait_for_ip(ifname = interfacename, "
     "timeout = timeout, addrtypes = [ipv4, ipv6, static_ipv4, static_ipv6, "
     "dhcp_ipv4, dhcp_ipv6, auto_ipv6, link_local_ipv6])\n\
     wait for ip.\n"},
    {"get_err_info", (PyCFunction)get_err_info,
     METH_VARARGS|METH_KEYWORDS, "net.get_err_info(error = <errno> )\n\
     returns a string describing the errorcode passed in argument.\n"},
    {"get_hostname", (PyCFunction)get_hostname,
     METH_NOARGS, "net.get_hostname()\n\
     returns hostname.\n"},
    {"set_hostname", (PyCFunction)set_hostname,
     METH_VARARGS|METH_KEYWORDS, "net.set_hostname(hostname=hostname)\n\
     sets hostname.\n"},
    {"get_network_param", (PyCFunction)get_network_param,
     METH_VARARGS|METH_KEYWORDS, "net.get_network_param(object = IfName or "
     "Filename, paramname = SectionName_KeyName)\n\
     gets network config parameter.\n"},
    {"set_network_param", (PyCFunction)set_network_param,
     METH_VARARGS|METH_KEYWORDS, "net.set_network_param(object = IfName or "
     "Filename, paramname = SectionName_KeyName, paramvalue = KeyValue)\n\
     sets network config parameter.\n"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef net_members[] =
{
    {"server", T_OBJECT_EX, offsetof(PY_NET, server), 0,
     "server details"},
    {NULL}  /* Sentinel */
};

static PyGetSetDef net_getset[] = {
    {"firewall",
     (getter)net_py_getfirewall, (setter)NULL,
     "get firewall object",
     NULL},
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
