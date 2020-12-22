

# pmd

## Overview
Photon Management Daemon (pmd) provides secure remote management of
resources on linux machines.

pmd manages the following resources
* iptable rules
* network via network-config-manager component
* packages via tdnf
* users and groups

pmd provides the following ways to interact with the server
* cmd line client (pmd-cli) uses dce-rpc and srp to securely authenticate
* REST api (spec driven with openapi swagger 2.0)
* server openapi spec driven REST cmd line client (copenapi)
* python3 api


## Try it out

### Prerequisites

* vmware-rest, copenapi
* dcerpc
* gssapi-unix
* tdnf, network-config-manager
* rpm, jansson, krb5, curl, glib
* openldap, shadow, systemd
* c-rest-engine, python3, e2fsprogs
* openssl

### Build & Run

1. Install devel packages of above prerequisites as applicable.
2. From the source root directory, ./rebuild.sh
3. mkdir /etc/pmd && cp conf/* /etc/pmd
4. Server binary is server/pmd. run it in the background ./server/pmd &
5. ./tools/cli/pmd-cli and follow cmd line help. For eg: pmd-cli net get-hostname

## Documentation
### pmd-cli
These are the current registered components
 'firewall' : firewall management
 'net' : network management
 'pkg' : package management
 'usr' : user management
You need to specify a component and a command
usage: pmd-cli [connection/auth options] <component> <command> [command options]

For local connections, use: pmd-cli <component> <cmd> <options>.
Current logged in user permissions will apply when executing commands.
This is the same as specifying --servername localhost.
For remote servers, use method mentioned below.
Password is never sent out in clear to the remote in the below auth scenario.
When --user is specified, you will be prompted for password.
1. System user.
   pmd-cli <component> <cmd> <options> --servername <server> --user <user>

### REST interface
self documenting via conf/restapispec.json or copenapi client

### python
import pmd
help(pmd)
srv = pmd.server()
help(srv)
help(srv.net)

## Releases & Major Branches
Initial release 0.0.1

## Contributing

The pmd project team welcomes contributions from the community. If you wish to contribute code and you have not
signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any
questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq). For more detailed information,
refer to [CONTRIBUTING.md](CONTRIBUTING.md).

## License
pmd is available under the [Apache 2 license](LICENSE.txt).
