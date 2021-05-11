/*
 * Copyright © 2016-2021 VMware, Inc.  All Rights Reserved.
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


#ifndef __PKGMGMT_RPC_TYPES_H__
#define __PKGMGMT_RPC_TYPES_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DCE_IDL_

cpp_quote("#include <pkgmgmtrpctypes.h>")
cpp_quote("#if 0")

#endif

typedef struct _TDNF_RPC_CMD_OPT_
{
    unsigned32 nType;
    wstring_t pwszOptName;
    wstring_t pwszOptValue;
}TDNF_RPC_CMD_OPT, *PTDNF_RPC_CMD_OPT;

typedef struct _TDNF_RPC_CMD_OPT_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PTDNF_RPC_CMD_OPT pCmdOpt;
}TDNF_RPC_CMD_OPT_ARRAY, *PTDNF_RPC_CMD_OPT_ARRAY;

typedef struct _TDNF_RPC_CMD_ARGS_
{
    //Represent options in the dnf cmd line.
    //All options are one to one maps to dnf command line
    //options (incomplete)
    unsigned32 nAllowErasing;     //allow erasures when solving
    unsigned32 nAssumeNo;         //assume no for all questions
    unsigned32 nAssumeYes;        //assume yes for all questions
    unsigned32 nBest;             //resolve packages to latest version
    unsigned32 nCacheOnly;        //operate entirely from cache
    unsigned32 nDebugSolver;      //dump solv debug info
    unsigned32 nShowHelp;         //Show help
    unsigned32 nRefresh;          //expire metadata before running commands
    unsigned32 nRpmVerbosity;     //set to rpm verbosity level
    unsigned32 nShowDuplicates;   //show dups in list/search
    unsigned32 nShowVersion;      //show version and exit
    unsigned32 nNoGPGCheck;       //skip gpg check
    unsigned32 nVerbose;          //print debug info
    unsigned32 nIPv4;             //resolve to IPv4 addresses only
    unsigned32 nIPv6;             //resolve to IPv6 addresses only
    wstring_t pwszInstallRoot;  //set install root
    wstring_t pwszConfFile;     //set conf file location
    wstring_t pwszReleaseVer;   //Release version

    //Commands and args that do not fall in options
    PPMD_WSTRING_ARRAY pCmds;
    PTDNF_RPC_CMD_OPT_ARRAY pSetOptArray;
}TDNF_RPC_CMD_ARGS, *PTDNF_RPC_CMD_ARGS;

typedef struct _TDNF_RPC_REPODATA_
{
    unsigned32 nEnabled;
    wstring_t  pwszId;
    wstring_t  pwszName;
}TDNF_RPC_REPODATA, *PTDNF_RPC_REPODATA;

typedef struct _TDNF_RPC_CLEAN_INFO_
{
    unsigned32 nCleanAll;
    unsigned32 nRpmDbFilesRemoved;
    unsigned32 nMetadataFilesRemoved;
    unsigned32 nDbCacheFilesRemoved;
    unsigned32 nPackageFilesRemoved;
    PPMD_WSTRING_ARRAY pszReposUsed;
}TDNF_RPC_CLEAN_INFO, *PTDNF_RPC_CLEAN_INFO;

typedef struct _TDNF_RPC_REPODATA_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PTDNF_RPC_REPODATA pRepoData;
}TDNF_RPC_REPODATA_ARRAY, *PTDNF_RPC_REPODATA_ARRAY;

typedef struct _TDNF_RPC_PKGINFO_
{
    unsigned32 dwEpoch;
    unsigned32 dwSize;
    wstring_t  pwszName;
    wstring_t  pwszVersion;
    wstring_t  pwszArch;
    wstring_t  pwszRepoName;
    wstring_t  pwszSummary;
    wstring_t  pwszDescription;
    wstring_t  pwszFormattedSize;
    wstring_t  pwszRelease;
    wstring_t  pwszLicense;
    wstring_t  pwszUrl;
}TDNF_RPC_PKGINFO, *PTDNF_RPC_PKGINFO;

typedef struct _TDNF_RPC_PKGINFO_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PTDNF_RPC_PKGINFO pPkgInfo;
}TDNF_RPC_PKGINFO_ARRAY, *PTDNF_RPC_PKGINFO_ARRAY;

typedef struct _TDNF_RPC_SOLVED_PKG_INFO_
{
    unsigned32 nNeedAction;
    unsigned32 nNeedDownload;
    unsigned32 nAlterType;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsNotAvailable;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsExisting;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsToInstall;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsToDowngrade;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsToUpgrade;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsToRemove;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsUnNeeded;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsToReinstall;
    PTDNF_RPC_PKGINFO_ARRAY pPkgsObsoleted;
    PPMD_WSTRING_ARRAY pPkgsNotResolved;
}TDNF_RPC_SOLVED_PKG_INFO, *PTDNF_RPC_SOLVED_PKG_INFO;

typedef struct _TDNF_RPC_UPDATEINFO_REF_
{
    wstring_t pwszID;
    wstring_t pwszLink;
    wstring_t pwszTitle;
    wstring_t pwszType;
}TDNF_RPC_UPDATEINFO_REF, *PTDNF_RPC_UPDATEINFO_REF;

typedef struct _TDNF_RPC_UPDATEINFO_REF_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PTDNF_RPC_UPDATEINFO_REF pUpdateInfoRefs;
}TDNF_RPC_UPDATEINFO_REF_ARRAY, *PTDNF_RPC_UPDATEINFO_REF_ARRAY;

typedef struct _TDNF_RPC_UPDATEINFO_PKG_
{
    wstring_t pwszName;
    wstring_t pwszFileName;
    wstring_t pwszEVR;
    wstring_t pwszArch;
}TDNF_RPC_UPDATEINFO_PKG, *PTDNF_RPC_UPDATEINFO_PKG;

typedef struct _TDNF_RPC_UPDATEINFO_PKG_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PTDNF_RPC_UPDATEINFO_PKG pUpdateInfoPkgs;
}TDNF_RPC_UPDATEINFO_PKG_ARRAY, *PTDNF_RPC_UPDATEINFO_PKG_ARRAY;

typedef struct _TDNF_RPC_UPDATEINFO_
{
    unsigned32 nType;
    wstring_t pwszID;
    wstring_t pwszDate;
    wstring_t pwszDescription;
    PTDNF_RPC_UPDATEINFO_REF_ARRAY pReferences;
    PTDNF_RPC_UPDATEINFO_PKG_ARRAY pPackages;
}TDNF_RPC_UPDATEINFO, *PTDNF_RPC_UPDATEINFO;

typedef struct _TDNF_RPC_UPDATEINFO_SUMMARY_
{
    unsigned32 nCount;
    unsigned32 nType;
}TDNF_RPC_UPDATEINFO_SUMMARY, *PTDNF_RPC_UPDATEINFO_SUMMARY;

typedef struct _TDNF_RPC_UPDATEINFO_SUMMARY_ARRAY_
{
    unsigned32 dwCount;
#ifdef _DCE_IDL_
    [size_is(dwCount)]
#endif
    PTDNF_RPC_UPDATEINFO_SUMMARY pRpcUpdateInfoSummaries;
}TDNF_RPC_UPDATEINFO_SUMMARY_ARRAY, *PTDNF_RPC_UPDATEINFO_SUMMARY_ARRAY;

#ifdef _DCE_IDL_
cpp_quote("#endif")
#endif

#ifdef __cplusplus
}
#endif

#endif /* __PKGMGMT_RPC_TYPES_H__ */
