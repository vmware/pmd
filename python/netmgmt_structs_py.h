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


#pragma once

typedef enum _DHCPMode
{
        DHCP_MODE_NO,
        DHCP_MODE_YES,
        DHCP_MODE_IPV4,
        DHCP_MODE_IPV6,
        _DHCP_MODE_MAX,
        _DHCP_MODE_INVALID = -1
} DHCPMode;

typedef struct _PY_NET_
{
    PyObject_HEAD
    PyObject *server;
    PPMDHANDLE hHandle;

}PY_NET, *PPY_NET;

typedef struct _PY_SYSTEM_
{
    PyObject_HEAD
    PyObject *pDnsMode;
    PyObject *pServersList;
    PyObject *pDomainsList;
    PyObject *pNtpServersList;
}PY_SYSTEM, *PPY_SYSTEM;

typedef struct _PY_LINK_
{
    PyObject_HEAD
    PyObject *pInterface_name;
    PyObject *pMacAddress;
    PyObject *pLinkMode;
    PyObject *pLinkState;
    int link_mtu;
    PyObject *pIpv4AddrMode;
    PyObject *pIpv4_addr;
    PyObject *pIpv4_gateway;
    PyObject *ipv6_dhcp_enabled;
    PyObject *ipv6_autoconf_enabled;
    PyObject *pIpv6_gateway;
    PyObject *pIpv6_addr_list;
    PyObject *pIP_Route_Info;
    PyObject *pDuid;
    PyObject *pIaid;
    PyObject *pDnsMode;
    PyObject *pServersList;
    PyObject *pDomainsList;
}PY_LINK, *PPY_LINK;

typedef struct _PY_IP_ROUTE_
{
    PyObject_HEAD
    PyObject *pRouteDestNetwork;
    PyObject *pRouteSourceNetwork;
    PyObject *pRouteGateway;
    int scope;
    int metric;
    int table;
}PY_IP_ROUTE, *PPY_IP_ROUTE;
