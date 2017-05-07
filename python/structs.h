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

typedef struct _PY_PMD_
{
    PyObject_HEAD
}PY_PMD, *PPY_PMD;

typedef struct _PY_PMD_SERVER_
{
    PyObject_HEAD
    PyObject *name;
    PyObject *user;
    PyObject *domain;
    PyObject *pass;
    PyObject *spn;
}PY_PMD_SERVER, *PPY_PMD_SERVER;

typedef struct _PY_PKG_
{
    PyObject_HEAD
    PyObject *server;
    PPMDHANDLE hHandle;
}PY_PKG, *PPY_PKG;

typedef struct _PY_PKG_REPODATA
{
    PyObject_HEAD
    PyObject *id;
    PyObject *name;
    PyObject *baseurl;
    int enabled;
}PY_PKG_REPODATA, *PPY_PKG_REPODATA;

typedef struct _PY_PKG_PACKAGE
{
    PyObject_HEAD
    PyObject *name;
    PyObject *version;
    PyObject *arch;
    PyObject *reponame;
    PyObject *summary;
    PyObject *description;
    PyObject *sizeFormatted;
    PyObject *release;
    PyObject *license;
    PyObject *url;
    int epoch;
    int size;
}PY_PKG_PACKAGE, *PPY_PKG_PACKAGE;

typedef struct _PY_PKG_SOLVED_INFO_
{
    PyObject_HEAD
    int needAction;
    int needDownload;
    TDNF_ALTERTYPE alterType;
    PyObject *pkgsNotAvailable;
    PyObject *pkgsExisting;
    PyObject *pkgsToInstall;
    PyObject *pkgsToDowngrade;
    PyObject *pkgsToUpgrade;
    PyObject *pkgsToRemove;
    PyObject *pkgsUnNeeded;
    PyObject *pkgsToReinstall;
    PyObject *pkgsObsoleted;
    PyObject *pkgsNotResolved;
}PY_PKG_SOLVED_INFO, *PPY_PKG_SOLVED_INFO;

typedef struct _PY_FIREWALL_
{
    PyObject_HEAD
    PyObject *server;
    PPMDHANDLE hHandle;
}PY_FIREWALL, *PPY_FIREWALL;
