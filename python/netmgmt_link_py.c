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

static char link__doc__[] = "";

static void
link_dealloc(PY_LINK *self)
{
    Py_XDECREF(self->pInterface_name);
    Py_XDECREF(self->pMacAddress);
    Py_XDECREF(self->pLinkMode);
    Py_XDECREF(self->pLinkState);
    Py_XDECREF(self->pIpv4_addr);
    Py_XDECREF(self->pIpv4_gateway);
    Py_XDECREF(self->ipv6_dhcp_enabled);
    Py_XDECREF(self->ipv6_autoconf_enabled);
    Py_XDECREF(self->pIpv6_gateway);
    Py_XDECREF(self->pIpv6_addr_list);
    Py_XDECREF(self->pIP_Route_Info);
    Py_XDECREF(self->pDuid);
    Py_XDECREF(self->pIaid);
    Py_XDECREF(self->pDnsMode);
    Py_XDECREF(self->pServersList);
    Py_XDECREF(self->pDomainsList);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *
link_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PPY_LINK self;

    self = (PPY_LINK)type->tp_alloc(type, 0);
    if (self != NULL)
    {
    }

    return (PyObject *)self;
}

static int
link_init(PY_LINK *self, PyObject *args, PyObject *kwds)
{
    PyObject *server = NULL;

    if (! PyArg_ParseTuple(args, "O", &server))
    {
        return -1;
    }

    return 0;
}


PyObject*
link_repr(
    PyObject *self
    )
{
    uint32_t dwError = 0;
    PyObject *pyRepr = Py_None;
    PPY_LINK pLink = NULL;
    char *pszRepr = NULL;

    pLink = (PPY_LINK)self;
    dwError = PMDAllocateStringPrintf(
                  &pszRepr,
                  "{ Interface Name: %s, MAC Address: %s, Link Mode: %s, "
                  "Link State: %s, Link Mtu: %d, IPV4 Address Mode: %s, "
                  "IPV4 Address: %s, IPV4 Gateway: %s, "
                  "IPV6 DHCP enabled: %s, IPV6 autoconf_enabled: %s, "
                  "IPV6 Gateway: %s, IPV6 Addrlist: %s, "
                  "DUID: %s, IAID: %s, "
                  "DNS Mode: %s, DNS ServerList: %s, DNS DomainList: %s, "
                  "Route Info: %s }",
                  (pLink->pInterface_name != Py_None) ?
                  PyBytes_AsString(pLink->pInterface_name) : "",
                  (pLink->pMacAddress != Py_None) ?
                  PyBytes_AsString(pLink->pMacAddress) : "",
                  (pLink->pLinkMode != Py_None) ?
                  PyBytes_AsString(pLink->pLinkMode) : "",
                  (pLink->pLinkState != Py_None) ?
                  PyBytes_AsString(pLink->pLinkState) : "",
                  pLink->link_mtu,
                  (pLink->pIpv4AddrMode != Py_None) ?
                  PyBytes_AsString(pLink->pIpv4AddrMode) : "",
                  (pLink->pIpv4_addr != Py_None) ?
                  PyBytes_AsString(pLink->pIpv4_addr) : "",
                  (pLink->pIpv4_gateway != Py_None) ?
                  PyBytes_AsString(pLink->pIpv4_gateway) : "",
                  (pLink->ipv6_dhcp_enabled != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pLink->ipv6_dhcp_enabled))
                  : "",
                  (pLink->ipv6_autoconf_enabled != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pLink->ipv6_autoconf_enabled))
                  : "",
                  (pLink->pIpv6_gateway != Py_None) ?
                  PyBytes_AsString(pLink->pIpv6_gateway) : "",
                  (pLink->pIpv6_addr_list != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pLink->pIpv6_addr_list)) : "",
                  (pLink->pDuid != Py_None) ? PyBytes_AsString(pLink->pDuid)
                  : "",
                  (pLink->pIaid != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pLink->pIaid)) : "" ,
                  (pLink->pDnsMode != Py_None) ?
                  PyBytes_AsString(pLink->pDnsMode) : "",
                  (pLink->pServersList != Py_None)?
                  PyBytes_AsString(PyObject_Str(pLink->pServersList)) : "",
                  (pLink->pDomainsList != Py_None) ?
                  PyBytes_AsString(PyObject_Str(pLink->pDomainsList)) : "",
                  PyBytes_AsString(PyObject_Str(pLink->pIP_Route_Info)));
    BAIL_ON_PMD_ERROR(dwError);

    pyRepr = Py_BuildValue("s", pszRepr);

cleanup:
    PMD_SAFE_FREE_MEMORY(pszRepr);
    return pyRepr;

error:
    printf("Error = %d\n", dwError);
    pyRepr = Py_None;
    goto cleanup;
}

PyObject*
link_str(
    PyObject *self
    )
{
    return link_repr(self);
}

static PyGetSetDef link_getset[] = {
    {NULL}  /* Sentinel */
};

static PyMethodDef link_methods[] =
{
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static PyMemberDef link_members[] =
{
    {"interface_name", T_OBJECT_EX, offsetof(PY_LINK, pInterface_name), 0,
     "interface name"},
    {"mac_address", T_OBJECT_EX, offsetof(PY_LINK, pMacAddress), 0,
     "mac address of interface"},
    {"link_mode", T_OBJECT_EX, offsetof(PY_LINK, pLinkMode), 0,
     "mode of interface"},
    {"link_state", T_OBJECT_EX, offsetof(PY_LINK, pLinkState), 0,
     "state of the interface"},
    {"link_mtu", T_INT, offsetof(PY_LINK, link_mtu), 0,
     "mtu of the interface"},
    {"ipv4_address_mode", T_OBJECT_EX, offsetof(PY_LINK, pIpv4AddrMode), 0,
     "address mode of interface"},
    {"ipv4_address", T_OBJECT_EX, offsetof(PY_LINK, pIpv4_addr), 0,
     "ipv4 address of this interface"},
    {"ipv4_gateway", T_OBJECT_EX, offsetof(PY_LINK, pIpv4_gateway), 0,
     "ipv4 gateway of the interface"},
    {"ipv6_dhcp_enabled", T_OBJECT_EX, offsetof(PY_LINK, ipv6_dhcp_enabled), 0,
     "whether ipv6 is dhcp enabled"},
    {"ipv6_autoconf_enabled", T_OBJECT_EX,
     offsetof(PY_LINK, ipv6_autoconf_enabled), 0,
     "is auto configuration enabled for ipv6"},
    {"ipv6_gateway", T_OBJECT_EX, offsetof(PY_LINK, pIpv6_gateway), 0,
     "ipv6 gateway of this interface"},
    {"ipv6_addr_list", T_OBJECT_EX, offsetof(PY_LINK, pIpv6_addr_list), 0,
     "ipv6 addresses of this interface"},
    {"ip_route", T_OBJECT_EX, offsetof(PY_LINK, pIP_Route_Info), 0,
     "route info of this interface"},
    {"duid", T_OBJECT_EX, offsetof(PY_LINK, pDuid), 0, "duid of the interface"},
    {"iaid", T_OBJECT_EX, offsetof(PY_LINK, pIaid), 0,
     "iaid of the interface"},
    {"dns_mode", T_OBJECT_EX, offsetof(PY_LINK, pDnsMode), 0,
     "mode of dns"},
    {"dns_servers", T_OBJECT_EX, offsetof(PY_LINK, pServersList), 0,
     "list of dns servers for this interface"},
    {"dns_domains", T_OBJECT_EX, offsetof(PY_LINK, pDomainsList), 0,
     "list of dns domains for this interface"},
    {NULL}  /* Sentinel */
};

PyTypeObject linkType = {
    PyVarObject_HEAD_INIT(&PyType_Type, 0)
    "net.link",                /*tp_name*/
    sizeof(PY_LINK),           /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)link_dealloc,  /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    link_repr,                 /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    link_str,                  /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    link__doc__,                /* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    link_methods,               /* tp_methods */
    link_members,               /* tp_members */
    link_getset,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)link_init,        /* tp_init */
    0,                         /* tp_alloc */
    link_new,                   /* tp_new */
    0,                         /* tp_free */
    0                          /* tp_is_gc */
};
