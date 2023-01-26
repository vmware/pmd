## photon-mgmtd


`photon-mgmtd` is a high performance open-source, simple, and pluggable REST API gateway designed with stateless architecture. It is written in Go, and built with performance in mind. It features real time health monitoring, configuration and performance for systems (containers), networking and applications.

- Proactive Monitoring and Analytics
  easy to gather statistics and perform analyses.
- Platform independent REST APIs can be accessed via any application (curl, chrome, PostMan ...) from any OS (Linux, IOS, Android, Windows ...)
- Minimal data transfer using JSON.
- Plugin based Architechture. See how to write plugin section for more information.

### Features!

|Feature| Details |
| ------ | ------ |
|systemd  | information, services (start, stop, restart, status), service properties for example CPUShares
see information from ```/proc``` fs| netstat, netdev, memory , vms, ARP and much more
system | fetch and configure system information for example hostname
network | fetch and configure network information example (dns, iostat, interface)
network link | configure network link parameters like (dhcp, linkLocalAddressing, multicastDNS, Address, route, domains, dns, ntp, ipv6AcceptRA, mode, mtubytes, mac, group, requiredFamilyForOnline, activationPolicy, routingPolicyRule, DHCPv4, DHCPv6, DHCPServer, Ipv6SendRA) etc
login | fetch list of users and sessions also get information for a id
network devices | create and remove virtual network devices like (Vlan, Bond, Bridge, MacVLan, IpVLan, VxLan, WireGuard) etc
ethtool | fetch ethernet settings for a link also based on a action
sysctl | used to fetch, set, load and automate kernel parameters
user | used to fetch, add, and remove user on the system
group | used to fetch, add, and remove group on the system
link | configure link parameters like (MACAddress, Name, AlternativeNames, Offload, VLANTAG, CHannels, Buffers, Queues, FlowControls, Coalesce) etc
firewall | add, delete and show nft tables, chain and rules also is used to run any NFT commands
package management (tdnf) | used to manage package management on the system like (list, info, download, update, remove, clean cache, list repositories, search package) etc

#### Building and installation from source
----

```bash

❯ make build
❯ sudo make install
```

Due to security `photon-mgmtd` runs in non root user `photon-mgmt`. It drops all privileges except `CAP_NET_ADMIN` and `CAP_SYS_ADMIN`.

```bash

❯  useradd -M -s /usr/bin/nologin photon-mgmt
```

#### Configuration
----

Configuration file `mgmt.toml` located in `/etc/photon-mgmt/` directory to manage the configuration.

The `[System]` section takes following Keys:

`LogLevel=`

Specifies the log level. Takes one of `Trace`, `Debug`, `Info`, `Warning`, `Error`, `Fatal` and `Panic`. Defaults to `info`. See [sirupsen](https://github.com/sirupsen/logrus#level-logging)

`UseAuthentication=`
A boolean. Specifies whether the users should be authenticated. Defaults to `true`.

The `[Network]` section takes following Keys:

`Listen=`
Specifies the IP address and port which the REST API server will listen to. When enabled, defaults to `127.0.0.1:5208`.

`ListenUnixSocket=`
A boolean. Specifies whether the server would listen on a unix domain socket `/run/photon-mgmt/mgmt.sock`. Defaults to `true`.

Note that when both `ListenUnixSocket=` and `Listen=` are enabled, server listens on the unix domain socket by default.
 ```bash
❯ sudo cat /etc/photon-mgmt/mgmt.toml
[System]
LogLevel="debug"
UseAuthentication="false"

[Network]
ListenUnixSocket="true"
```

```bash
❯ sudo systemctl status photon-mgmtd.service
● photon-mgmtd.service - A REST API based configuration management microservice gateway
     Loaded: loaded (/usr/lib/systemd/system/photon-mgmtd.service; disabled; vendor preset: disabled)
     Active: active (running) since Thu 2022-01-06 16:32:19 IST; 4s ago
   Main PID: 230041 (photon-mgmtd)
      Tasks: 6 (limit: 15473)
     Memory: 2.9M
        CPU: 7ms
     CGroup: /system.slice/photon-mgmtd.service
             └─230041 /usr/bin/photon-mgmtd

Jan 06 16:32:19 Zeus systemd[1]: photon-mgmtd.service: Passing 0 fds to service
Jan 06 16:32:19 Zeus systemd[1]: photon-mgmtd.service: About to execute /usr/bin/photon-mgmtd
Jan 06 16:32:19 Zeus systemd[1]: photon-mgmtd.service: Forked /usr/bin/photon-mgmtd as 230041
Jan 06 16:32:19 Zeus systemd[1]: photon-mgmtd.service: Changed failed -> running
Jan 06 16:32:19 Zeus systemd[1]: photon-mgmtd.service: Job 56328 photon-mgmtd.service/start finished, result=done
Jan 06 16:32:19 Zeus systemd[1]: Started photon-mgmtd.service - A REST API based configuration management microservice gateway.
Jan 06 16:32:19 Zeus systemd[230041]: photon-mgmtd.service: Executing: /usr/bin/photon-mgmtd
Jan 06 16:32:19 Zeus photon-mgmtd[230041]: time="2022-01-06T16:32:19+05:30" level=info msg="photon-mgmtd: v0.1 (built go1.18beta1)"
Jan 06 16:32:19 Zeus photon-mgmtd[230041]: time="2022-01-06T16:32:19+05:30" level=info msg="Starting photon-mgmtd... Listening on unix domain socket='/run/photon-mgmt/photon-mgmt>
```

#### pmctl
----

`pmctl` is a CLI tool allows to view and configure system/network/service status.

```bash
❯ pmctl service status nginx.service
                  Name: nginx.service
           Description: The nginx HTTP and reverse proxy server
               MainPid: 45732
             LoadState: loaded
           ActiveState: active
              SubState: running
         UnitFileState: disabled
  StateChangeTimeStamp: Sun Oct 31 12:02:02 IST 2021
  ActiveEnterTimestamp: Sun Oct 31 12:02:02 IST 2021
 InactiveExitTimestamp: Sun Oct 31 12:02:02 IST 2021
   ActiveExitTimestamp: 0
 InactiveExitTimestamp: Sun Oct 31 12:02:02 IST 2021
                Active: active (running) since Sun Oct 31 12:02:02 IST 2021

```

#### Configure system hostname
```bash
❯ pmctl system set-hostname static ubuntu transient transientname pretty prettyname
```

#### Acquire system status
```bash
❯ pmctl status  system
              System Name: Zeus
                   Kernel: Linux (5.14.0-0.rc7.54.fc36.x86_64) #1 SMP Mon Aug 23 13:55:32 UTC 2021
                  Chassis: vm
           Hardware Model: VMware Virtual Platform
          Hardware Vendor: VMware, Inc.
             Product UUID: 979e4d56b63718b18534e112e64cb18
         Operating System: VMware Photon OS/Linux
Operating System Home URL: https://vmware.github.io/photon/
          Systemd Version: v247.10-3.ph4
             Architecture: x86-64
           Virtualization: vmware
            Network State: routable (carrier)
     Network Online State: online
                      DNS: 172.16.130.2
                  Address: 172.16.130.132/24 on link ens33
                           172.16.130.131/24 on link ens33
                           fe80::3279:c56d:55f9:aed7/64 on link ens33
                           172.16.130.138/24 on link ens37
                  Gateway: 172.16.130.2 on link ens37
                           172.16.130.2 on link ens33
                   Uptime: Running Since (2 days, 3 hours, 8 minutes) Booted (Wed Dec 22 15:57:24 IST 2021) Users (9) Proc (284)
                   Memory: Total (13564788736) Used (13564788736) Free (589791232) Available (9723891712)
```

#### Network status
```bash
❯ pmctl status network -i ens33
             Name: ens33
Alternative Names: enp2s1
            Index: 2
        Link File: /usr/lib/systemd/network/99-default.link
     Network File: /etc/systemd/network/10-ens33.network
             Type: ether
            State: routable (configured)
           Driver: e1000
           Vendor: Intel Corporation
            Model: 82545EM Gigabit Ethernet Controller (Copper) (PRO/1000 MT Single Port Adapter)
             Path: pci-0000:02:01.0
    Carrier State: carrier
     Online State: online
IPv4Address State: routable
IPv6Address State: degraded
       HW Address: 00:0c:29:5f:d1:39
              MTU: 1500
        OperState: up
            Flags: up|broadcast|multicast
        Addresses: 172.16.130.132/24 172.16.130.131/24 fe80::3279:c56d:55f9:aed7/64
          Gateway: 172.16.130.2
              DNS: 172.16.130.2
```

#### Network dns status
```bash
> pmctl status network dns
Global

        DNS: 8.8.8.1 8.8.8.2
DNS Domains: test3.com test4.com . localdomain . localdomain
Link 2 (ens33)
Current DNS Server:  172.16.61.2
       DNS Servers:  172.16.61.2

Link 3 (ens37)
Current DNS Server:  172.16.61.2
       DNS Servers:  172.16.61.2
```

#### Network iostat status
```bash
> pmctl status network iostat
            Name: lo
Packets received: 7510
  Bytes received: 7510
      Bytes sent: 7510
         Drop in: 7510
        Drop out: 0
        Error in: 0
       Error out: 0
         Fifo in: 0
        Fifo out: 0

            Name: ens33
Packets received: 46014
  Bytes received: 19072
      Bytes sent: 19072
         Drop in: 19072
        Drop out: 0
        Error in: 0
       Error out: 0
         Fifo in: 0
        Fifo out: 0

            Name: ens37
Packets received: 9682
  Bytes received: 10779
      Bytes sent: 10779
         Drop in: 10779
        Drop out: 0
        Error in: 0
       Error out: 0
         Fifo in: 0
        Fifo out: 0
```

#### Network interfaces status
```bash
> pmctl status network interfaces
            Name: lo
           Index: 1
             MTU: 65536
           Flags: up loopback
Hardware Address:
       Addresses: 127.0.0.1/8 ::1/128

            Name: ens33
           Index: 2
             MTU: 1500
           Flags: up broadcast multicast
Hardware Address: 00:0c:29:7c:6f:84
       Addresses: 172.16.61.128/24 fe80::c099:2598:cc4c:14d1/64

            Name: ens37
           Index: 3
             MTU: 1500
           Flags: up broadcast multicast
Hardware Address: 00:0c:29:7c:6f:8e
       Addresses: 172.16.61.134/24 fe80::be9:7746:7729:3e2/64
```

#### Login status
```bash

#ListUsers
>pmctl status login user

#ListSessions
>pmctl status login session

#Get User based on UID
pmctl status login user <UID>
>pmctl status login user 2

#Get Session based on ID
pmctl status login session <ID>
>pmctl status login session 1000

```

#### Ethtool status
```bash

#Get Ethtool all status
pmctl status ethtool <LINK>
>pmctl status ethtool ens37

#Get Ethtool status based on action
pmctl status ethtool <LINK> <ACTION>
>pmctl status ethtool ens37 bus

```

#### sysctl usecase via pmctl
```bash

# Get all sysctl configuration in the system in json format.
pmctl status sysctl

# Get particuller variable configuration from sysctl configuration.
pmctl status sysctl k <InputKey>
or
pmctl status sysctl key <InputKey>

>pmctl status sysctl k fs.file-max
fs.file-max: 9223372036854775807

# Get all variable configuration from sysctl configuration based on input pattern.
pmctl status sysctl p <InputPatern>
or
pmctl status sysctl pattern <InputPatern>

>pmctl status sysctl p net.ipv6.route.gc
{"net.ipv6.route.gc_elasticity":"9","net.ipv6.route.gc_interval":"30","net.ipv6.route.gc_min_interval":"0","net.ipv6.route.gc_min_interval_ms":"500","net.ipv6.route.gc_thresh":"1024","net.ipv6.route.gc_timeout":"60"}

# Add or Update a variable configuration in sysctl configuration.
pmctl sysctl u -k <InputKey> -v <InputValue> -f <InputFile>
or
pmctl sysctl update key <InputKey> value <InputValue> filename <InputFile>

>pmctl sysctl u -k fs.file-max -v 65566 -f 99-sysctl.conf
>pmctl sysctl u -k fs.file-max -v 65566

# Remove a variable configuration from sysctl configuration.
pmctl sysctl r -k <InputKey> -f <InputFile>
or
pmctl sysctl remove key <InputKey> filename <InputFile>

>pmctl sysctl r -k fs.file-max -f 99-sysctl.conf
>pmctl sysctl r -k fs.file-max

# Load sysctl configuration files.
pmctl sysctl l -f <InputfileList>
or
pmctl sysctl load files <InputFileList>

>pmctl sysctl l -f 99-sysctl.conf,70-sysctl.conf
>pmctl sysctl l -f
```

#### sysctl usecase via curl
```bash

# Get all sysctl configuration in the system in json format.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET http://localhost/api/v1/system/sysctl/statusall
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET http://localhost/api/v1/system/sysctl/statusall

# Get particuller variable configuration from sysctl configuration.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET --data '{"key":"<keyName>"}' http://localhost/api/v1/system/sysctl/status
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET --data '{"key":"fs.file-max"}' http://localhost/api/v1/system/sysctl/status

# Get all variable configuration from sysctl configuration based on input pattern.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET --data '{"pattern":"<Pattern>"}' http://localhost/api/v1/system/sysctl/statuspattern
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET --data '{"pattern":"fs.file"}' http://localhost/api/v1/system/sysctl/statuspattern

# Add or Update a variable configuration in sysctl configuration.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"apply":true,"key":"<keyName>","value":"<Value>","filename":"<fileName>"}' http://localhost/api/v1/system/sysctl/update
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"apply":true,"key":"fs.file-max","value":"65409","filename":"99-sysctl.conf"}' http://localhost/api/v1/system/sysctl/update

# Remove a variable configuration from sysctl configuration.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request DELETE --data '{"apply":true,"key":"<keyName>","filename":"<fileName>"}' http://localhost/api/v1/system/sysctl/remove
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request DELETE --data '{"apply":true,"key":"fs.file-max","filename":"99-sysctl.conf"}' http://localhost/api/v1/system/sysctl/remove

# Load sysctl configuration files.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"apply":true,"files":["<fileName>","<fileName>"]}' http://localhost/api/v1/system/sysctl/load
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"apply":true,"files":["99-sysctl.conf","75-sysctl.conf"]}' http://localhost/api/v1/system/sysctl/load
```

#### Group usecase via pmctl
```bash

# Get all Group information.
>pmctl status group
             Gid: 0
            Name: root

             Gid: 1
            Name: daemon

             Gid: 2
            Name: bin

             Gid: 3
            Name: sys

             Gid: 4
            Name: adm
	    .
            .
            .
             Gid: 1001
            Name: photon-mgmt

# Fetch a group information.
pmctl status group <GroupName>
or
pmctl status group <GroupName>

>pmctl status group photon-mgmt
             Gid: 1001
            Name: photon-mgmt

# Add a new Group.
pmctl group add <GroupName> <Gid>
or
pmctl group add <GroupName>

# Remove a Group.
pmctl group remove <GroupName> <Gid>
or
pmctl group remove <GroupName>
```

#### Group usecase via curl
```bash

# Get all Group information.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET http://localhost/api/v1/system/group/view

# Get particuller Group information.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET http://localhost/api/v1/system/group/view/<GroupName>

# Add a new Group.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"Name":"<GroupName>","Gid":"<InputGid>"}' http://localhost/api/v1/system/group/add
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"Name":"nk1","Gid":"101"}' http://localhost/api/v1/system/group/add

# Remove a Group.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request DELETE --data '{"Name":"<GroupName>","Gid":"<InputGid>"}' http://localhost/api/v1/system/group/remove
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request DELETE --data '{"Name":"photon-mgmt","Gid":"101"}' http://localhost/api/v1/system/group/remove
```

#### User usecase via pmctl
```bash

# Get all User information.
>pmctl status user
          User Name: root
                Uid: 0
                Gid: 0
              GECOS: root
     Home Directory: /root

          User Name: daemon
                Uid: 1
                Gid: 1
              GECOS: daemon
     Home Directory: /usr/sbin

          User Name: bin
                Uid: 2
                Gid: 2
              GECOS: bin
     Home Directory: /bin

          User Name: sys
                Uid: 3
                Gid: 3
              GECOS: sys
     Home Directory: /dev

          User Name: photon-mgmt
                Uid: 1001
                Gid: 1001
     Home Directory: /home/photon-mgmt

# Add a new User.
pmctl user add <UserName> home-dir <HomeDir> groups <groupsList> uid <Uid> gid <Gid> shell <Shell> password <xxxxxxx>
or
pmctl user a <UserName> -d <HomeDir> -grp <groupsList> -u <Uid> -g <Gid> -s <Shell> -p <xxxxxxx>

# Remove a User.
pmctl user remove <UserName>
or
pmctl user r <UserName>
```

#### User usecase via curl
```bash

# Get all User information.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request GET http://localhost/api/v1/system/user/view

# Add a new User.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"Name":"<UserName>","Uid":"<Uid>","Gid":"<Gid>","Groups":["group1","group2"],""HomeDirectory":"<HomeDir>","Shell":"<shell>","Comment":"<comment>","Password":"<xxxxxx>"}' http://localhost/api/v1/system/user/add
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request POST --data '{"Name":"nts1","Uid":"","Gid":"1004","Groups":["nts","group2"],"HomeDirectory":"home/nts","Shell":"","Comment":"hello","Password":"unknown"}' http://localhost/api/v1/system/user/add

# Remove a User.
curl --unix-socket /run/photon-mgmt/mgmt.sock --request DELETE --data '{"Name":"<UserName>"}' http://localhost/api/v1/system/user/remove
>curl --unix-socket /run/photon-mgmt/mgmt.sock --request DELETE --data '{"Name":"nts1"}' http://localhost/api/v1/system/user/remove
```

#### Configure network link section using pmctl
```bash

# Configure network dhcp
pmctl network set-dhcp <deviceName> <DHCPMode>
>pmctl network set-dhcp ens37 ipv4

# Configure network linkLocalAddressing
pmctl network set-link-local-addr <deviceName> <linkLocalAddressingMode>
>pmctl network set-link-local-addr ens37 ipv4

# Configure network multicastDNS
pmctl network set-multicast-dns <deviceName> <MulticastDNSMode>
>pmctl network set-multicast-dns ens37 resolve

# Configure network address
pmctl network add-link-address <deviceName> address <Address> peer <Address> label <labelValue> scope <scopeValue>
>pmctl network add-link-address ens37 address 192.168.0.15/24 peer 192.168.10.10/24 label ipv4 scope link

# Configure network sriov
pmctl network add-sriov dev <deviceName> vf <VirtualFunction> vlanid <VLANId> qos <QualityOfService> vlanproto <VLANProtocol> macsfc <MACSpoofCheck> qrss <QueryReceiveSideScaling> trust <Trust> linkstate <LinkState> macaddr <MACAddress>
>pmctl network add-sriov dev ens37 vf 2 vlanid 1 qos 1024 vlanproto 802.1Q macsfc yes qrss yes trust yes linkstate auto macaddr 00:0c:29:3a:bc:11

# Configure network route
pmctl network add-route dev <deviceName> gw <Gateway> gwonlink <GatewayOnlink> src <Source> dest <Destination> prefsrc <preferredSource> table <Table> scope <Scope>
>pmctl network add-route dev ens33 gw 192.168.1.0 gwonlink no src 192.168.1.15/24 dest 192.168.10.10/24 prefsrc 192.168.8.9 table 1234 scope link

# Configure network dns
pmctl network add-dns dev <deviceName> dns <dnslist>
>pmctl network add-dns dev ens37 dns 8.8.8.8,8.8.4.4,8.8.8.1,8.8.8.2

#Configure network domains
pmctl network add-domain dev <deviceName> domains <domainlist>
>pmctl network add-domain dev ens37 domains test1.com,test2.com,test3.com,test4.com

#Configure network ntp
pmctl network add-ntp dev <deviceName> ntp <ntplist>
>pmctl network add-ntp dev ens37 ntp 198.162.1.15,test3.com

# Configure network ipv6AcceptRA
pmctl network set-ipv6-accept-ra <deviceName> <IPv6AcceptRA>
>pmctl network set-ipv6-accept-ra ens37 false

# Configure link mode
pmctl network set-link-mode dev <device> mode <unmanagedValue> arp <arpValue> mc <multicastValue> amc <allmulticastValue> pcs <PromiscuousValue> rfo <RequiredForOnline>
>pmctl network set-link-mode dev ens37 arp 1 mc no amc true pcs yes rfo on

# Configure link mtubytes
pmctl network set-mtu <deviceName> <mtubytesValue>
>pmctl network set-mtu ens37 2048

# Configure link mac
pmctl network set-mac <deviceName> <MACAddress>
>pmctl network set-gmac ens37 00:a0:de:63:7a:e6

# Configure link group
pmctl network set-group <deviceName> <groupValue>
>pmctl network set-group ens37 2147483647

# Configure link requiredFamilyForOnline
pmctl network set-rf-online <deviceName> <familyValue>
>pmctl network set-rf-online ens37 ipv4

# Configure link activationPolicy
pmctl network set-active-policy <deviceName> <policyValue>
>pmctl network set-active-policy ens37 always-up

# Configure network routingPolicyRule
pmctl network add-rule dev <deviceName> tos <TypeOfService> from <Address> to <Address> fwmark <FirewallMark> table <Table> prio <Priority> iif <IncomingInterface> oif <OutgoingInterface> srcport <SourcePort> destport <DestinationPort> ipproto <IPProtocol> invertrule <InvertRule> family <Family> usr <User> suppressprefixlen <SuppressPrefixLength> suppressifgrp <SuppressInterfaceGroup> type <Type>
>pmctl network add-rule dev ens37 tos 12 from 192.168.1.10/24 to 192.168.2.20/24 fwmark 7/255 table 8 prio 3 iif ens37 oif ens37 srcport 8000-8080 destport 9876 ipproto 17 invertrule yes family ipv4 usr 1001 suppressprefixlen 128 suppressifgrp 2098 type prohibit

# Remove network routingPolicyRule
pmctl network delete-rule dev <deviceName> tos <TypeOfService> from <Address> to <Address> fwmark <FirewallMark> table <Table> prio <Priority> iif <IncomingInterface> oif <OutgoingInterface> srcport <SourcePort> destport <DestinationPort> ipproto <IPProtocol> invertrule <InvertRule> family <Family> usr <User> suppressprefixlen <SuppressPrefixLength> suppressifgrp <SuppressInterfaceGroup> type <Type>
>pmctl network delete-rule dev ens37 tos 12 from 192.168.1.10/24 to 192.168.2.20/24 fwmark 7/255 table 8 prio 3 iif ens37 oif ens37 srcport 8000-8080 destport 9876 ipproto 17 invertrule yes family ipv4 usr 1001 suppressprefixlen 128 suppressifgrp 2098 type prohibit

# Configure network DHCPv4 id's
pmctl network set-dhcpv4-id dev <deviceName> clientid <ClientIdentifier> vendorclassid <VendorClassIdentifier> iaid <IAID>
>pmctl network set-dhcpv4-id dev ens37 clientid duid vendorclassid 101 iaid 201

# Configure network DHCPv4 duid
pmctl network set-dhcpv4-duid dev <deviceName> duidtype <DUIDType> duidrawdata <DUIDRawData>
>pmctl network set-dhcpv4-duid dev ens37 duidtype vendor duidrawdata af:03:ff:87

# Configure network DHCPv4 use options
pmctl network set-dhcpv4-use dev <deviceName> usedns <UseDNS> usentp <UseNTP> usesip <UseSIP> usemtu <UseMTU> usehostname <UseHostname> usedomains <UseDomains> useroutes <UseRoutes> usegateway <UseGateway> usetimezone <UseTimezone>
>pmctl network set-dhcpv4-use dev ens37 usedns false usentp false usesip false usemtu yes usehostname true usedomains yes useroutes no usegateway yes usetimezone no

# Configure network DHCPv6
pmctl network set-dhcpv6 dev <deviceName> mudurl <MUDURL> userclass <UserClass> vendorclass <VendorClass> prefixhint <IPV6ADDRESS> withoutra <WithoutRA>
>pmctl network set-dhcpv6 dev ens37 mudurl https://example.com/devB userclass usrcls1,usrcls2 vendorclass vdrcls1 prefixhint 2001:db1:fff::/64 withoutra solicit

# Configure network DHCPv6 id's
pmctl network set-dhcpv6-id dev <deviceName> iaid <IAID> duidtype <DUIDType> duidrawdata <DUIDRawData>
>pmctl network set-dhcpv6-id dev ens37 iaid 201 duidtype vendor duidrawdata af:03:ff:87

# Configure network DHCPv6 Use
pmctl network set-dhcpv6-use dev <deviceName> useaddr <UseAddress> useprefix <UsePrefix> usedns <UseDNS> usentp <UseNTP> usehostname <UseHostname> usedomains <UseDomains>
>pmctl network set-dhcpv6-use dev ens37 useaddr yes useprefix no usedns false usentp false usehostname true usedomains yes

# Configure network DHCPv6 Options
pmctl network set-dhcpv6-option dev <deviceName> reqopt <RequestOptions> sendopt <SendOption> sendvendoropt <SendVendorOption>
>pmctl network set-dhcpv6-option dev ens37 reqopt 10,198,34 sendopt 34563 sendvendoropt 1987653,65,ipv6address,af:03:ff:87

# Configure network DHCPServer
pmctl network add-dhcpv4-server dev <Devicename> pool-offset <poolOffset> pool-size <PoolSize> default-lease-time-sec <DefaultLeaseTimeSec> max-lease-time-sec <MaxLeaseTimeSec> dns <DNS> emit-dns <EmitDNS> emit-ntp <EmitNTP> emit-router <EmitRouter>
>pmctl network add-dhcpv4-server dev ens37 pool-offset 100 pool-size 200 default-lease-time-sec 10 max-lease-time-sec 30 dns 192.168.1.2,192.168.10.10,192.168.20.30 emit-dns yes emit-ntp no emit-router yes

# Remove network DHCPServer
pmctl network remove-dhcpv4-server <Devicename>
>pmctl network remove-dhcpv4-server ens37

# Configure network IPv6SendRA
pmctl network add-ipv6ra dev <deviceName> rt-pref <RouterPreference> emit-dns <EmitDNS> dns <DNS> emit-domains <EmitDomains> domains <Domains> dns-lifetime-sec <DNSLifetimeSec> prefix <Prefix> pref-lifetime-sec <PreferredLifetimeSec> valid-lifetime-sec <ValidLifetimeSec> assign <Assign> route <Route> lifetime-sec <LifetimeSec>
>pmctl network add-ipv6ra dev ens37 rt-pref medium emit-dns yes dns 2002:da8:1::1,2002:da8:2::1 emit-domains yes domains test1.com,test2.com dns-lifetime-sec 100 prefix 2002:da8:1::/64 pref-lifetime-sec 100 valid-lifetime-sec 200 assign yes route 2001:db1:fff::/64 lifetime-sec 1000

# Remove network IPv6SendRA
pmctl network remove-ipv6ra <Devicename>
>pmctl network remove-ipv6ra ens37

```

#### Configure network device using pmctl
```bash
# Configure VLan
pmctl network create-vlan <vlanName> dev <device> id <vlanId>
>pmctl network create-vlan vlan1 dev ens37 id 101

# Configure Bond
pmctl network create-bond <bondName> dev <device> mode <modeType> thp <TransmitHashPolicyType> ltr <LACPTransmitRateType> mms <MIIMonitorSecTime>
>pmctl network create-bond bond1 dev ens37,ens38 mode 802.3ad thp layer2+3 ltr slow mms 1s

# Configure Bond with default
>pmctl network create-bond bond1 dev ens37,ens38

# Configure Bridge with default
pmctl network create-bridge <bridgeName> dev <device list>
>pmctl network create-bridge br0 dev ens37,ens38

# Configure MacVLan
pmctl network create-macvlan <macvlanName> dev <device> mode <modeName>
>pmctl network create-macvlan macvlan1 dev ens37 mode private

# Configure IpVLan
pmctl network create-ipvlan <ipvlanName> dev <device> mode <modeName> flags <flagsName>
>pmctl network create-ipvlan ipvlan1 dev ens37 mode l2 flags vepa

# Configure IpVLan with default
>pmctl network create-ipvlan ipvlan1 dev ens38

# Configure VxLan
pmctl network create-vxlan <vxlanName> dev <device> remote <RemoteAddress> local <LocalAddress> group <GroupAddress> destport <DestinationPort> independent <IndependentFlag>
>pmctl network create-vxlan vxlan1 dev ens37 vni 16777215 remote 192.168.1.3 local 192.168.1.2 group 192.168.0.0 destport 4789 independent no

# Configure WireGuard
pmctl network create-wg <wireguardName> dev <device> skey <privateKey> pkey<publicKey> endpoint <address:Port> port <listenport> ips <allowedIPs>
>pmctl network create-wg wg1 dev ens37 skey wCmc/74PQpRoxTgqGircVFtdArZFUFIiOoyQY8kVgmI= pkey dSanSzExlryduCwNnAFt+rzpI5fKeHuJx1xx2zxEG2Q= endpoint 10.217.69.88:51820 port 51822 ips fd31:bf08:57cb::/48,192.168.26.0/24

# Configure WireGuard with default
>pmctl network create-wg wg1 dev ens37 skey wCmc/74PQpRoxTgqGircVFtdArZFUFIiOoyQY8kVgmI= pkey dSanSzExlryduCwNnAFt+rzpI5fKeHuJx1xx2zxEG2Q= endpoint 10.217.69.88:51820

# Configure Tun
pmctl network create-tun <tunName> dev <device> mq <MultiQueue> pktinfo<PacketInfo> vnet-hdr <VNetheader> usr <User> grp <Group> kc <KeepCarrier>
>pmctl network create-tun tun1 dev ens37 mq yes pktinfo yes vnet-hdr no usr test-user grp test-group kc no

# Configure Tap
pmctl network create-tap <tapName> dev <device> mq <MultiQueue> pktinfo<PacketInfo> vnet-hdr <VNetheader> usr <User> grp <Group> kc <KeepCarrier>
>pmctl network create-tap tap99 dev ens37 mq yes pktinfo yes vnet-hdr no usr test-user grp test-group kc no
```

#### Remove network device using pmctl
```bash
pmctl network remove-netdev <kindDeviceName> kind <kindType>
>pmctl network remove-netdev ipvlan1 dev ens37 kind ipvlan
```

#### Configure link using pmctl
```bash

# Configure Link MACAddress.
pmctl link set-mac dev <deviceName> macpolicy <MACAddressPolicy> macaddr <MACAddress>
>pmctl link set-mac dev eth0 macpolicy none macaddr 00:a0:de:63:7a:e6

# Configure Link Name.
pmctl link set-name dev <deviceName> namepolicy <NamePolicy> name <Name>
>pmctl link set-name dev ens37 namepolicy mac,kernel,database,onboard,keep,slot,path

# Configure Link AlternativeNames.
pmctl link set-name dev <deviceName> altnamespolicy <AlternativeNamesPolicy> altname <AlternativeName>
>pmctl link set-alt-name dev ens37 altnamespolicy mac,database,onboard,slot,path

# Configure Link ChecksumOffload.
pmctl link set-csum-offload dev <deviceName> rco <ReceiveCheksumOffload> tco <TransmitChecksumOffload>
>pmctl link set-csum-offload dev ens37 rxco true txco true

# Configure Link TCPSegmentationOffload.
pmctl link set-tcp-offload dev <deviceName> tcpso <TCPSegmentationOffload> tcp6so <TCP6SegmentationOffload>
>pmctl link set-tcp-offload dev ens37 tcpso true tcp6so true

# Configure Link GenericOffload.
pmctl link set-generic-offload dev <deviceName> gso <GenericSegmentationOffload> gro <GenericReceiveOffload> grohw <GenericReceiveOffloadHardware> gsomaxbytes <GenericSegmentOffloadMaxBytes> gsomaxseg <GenericSegementOffloadMaxSegments>
>pmctl link set-generic-offload dev ens37 gso true gro true grohw false gsomaxbytes 65536 gsomaxseg 65535

# Configure Link VLANTAG.
pmctl link set-vlan-tags dev <deviceName> rxvlanctaghwacl <ReceiveVLANCTAGHardwareAcceleration> txvlanctaghwacl <TransmitVLANCTAGHardwareAcceleration> rxvlanctagfilter <ReceiveVLANCTAGFilter> txvlanstaghwacl <TransmitVLANSTAGHardwareAcceleration>
>pmctl link set-vlan-tags dev ens37 rxvlanctaghwacl true txvlanctaghwacl false rxvlanctagfilter true txvlanstaghwacl true

# Configure Link Channels.
pmctl link set-channel dev <deviceName> rxch <RxChannels> txch <TxChannels> oth <OtherChannels> coch <CombinedChannels>
>pmctl link set-channel dev ens37 rxch 1024 txch 2045 och 45678 coch 32456

# Configure Link Buffers.
pmctl link set-buffer dev <deviceName> rxbufsz <RxBufferSize> rxmbufsz <RxMiniBufferSize> rxjbufsz <RxJumboBufferSize> txbufsz <TxBufferSize>
>pmctl link set-buffer dev ens37 rxbufsz 100009 rxmbufsz 1998 rxjbufsz 10999888 txbufsz 83724

# Configure Link Queues.
pmctl link set-queue dev <deviceName> rxq <ReceiveQueues> txq <TransmitQueues> txqlen <TransmitQueueLength>
>pmctl link set-queue dev ens37 rxq 4096 txq 4096 txqlen 4294967294

# Configure Link FlowControls.
pmctl link set-flow-ctrl dev <deviceName> rxfctrl <RxFlowControl> txfctrl <TxFlowControl> anfctrl <AutoNegotiationFlowControl>
>pmctl link set-flow-ctrl dev ens37 rxfctrl true txfctrl true anfctrl true

# Configure Link UseAdaptiveCoalesce.
pmctl link set-adpt-coalesce dev <deviceName> uarxc <UseAdaptiveRxCoalesce> uatxc <UseAdaptiveTxCoalesce>
>pmctl link set-adpt-coalesce dev ens37 uarxc true uatxc true

# Configure Link ReceiveCoalesce.
pmctl link set-rx-coalesce dev <deviceName> rxcs <RxCoalesceSec> rxcsirq <RxCoalesceIrqSec> rxcslow <RxCoalesceLowSec> rxcshigh <RxCoalesceHighSec>
>pmctl link set-rx-coalesce dev ens37 rxcs 23 rxcsirq 56 rxcslow 5 rxcshigh 76788

# Configure Link TransmitCoalesce.
pmctl link set-tx-coalesce dev <deviceName> txcs <TxCoalesceSec> txcsirq <TxCoalesceIrqSec> txcslow <TxCoalesceLowSec> txcshigh <TxCoalesceHighSec>
>pmctl link set-tx-coalesce dev ens37 txcs 23 txcsirq 56 txcslow 5 txcshigh 76788

# Configure Link ReceiveMaxCoalescedFrames.
pmctl link set-rx-coald-frames dev <deviceName> rxcmf <RxMaxCoalescedFrames> rxcmfirq <RxMaxCoalescedIrqFrames> rxcmflow <RxMaxCoalescedLowFrames> rxcmfhigh <RxMaxCoalescedHighFrames>
>pmctl link set-rx-coald-frames dev ens37 rxmcf 23 rxmcfirq 56 rxmcflow 5 rxmcfhigh 76788

# Configure Link TransmitMaxCoalescedFrames.
pmctl link set-tx-coald-frames dev <deviceName> txcmf <TxMaxCoalescedFrames> txcmfirq <TxMaxCoalescedIrqFrames> txcmflow <TxMaxCoalescedLowFrames> txcmfhigh <TxMaxCoalescedHighFrames>
>pmctl link set-tx-coald-frames dev ens37 txmcf 23 txmcfirq 56 txmcflow 5 txmcfhigh 76788

# Configure Link CoalescePacketRate.
pmctl link set-coalesce-pkt dev <deviceName> cprlow <CoalescePacketRateLow> cprhigh <CoalescePacketRateHigh> cprsis <CoalescePacketRateSampleIntervalSec>
>pmctl link set-coalesce-pkt dev ens37 cprlow 1000 cprhigh 32456 cprsis 102

# Configure Link Alias,Description,port,duplex...etc.
pmctl link set-link dev ens37 alias <Alias> desc <Description> mtub <MTUBytes> bits <BitsPerSecond> duplex <Duplex> auton <AutoNegotiation> wol <WakeOnLan> wolpassd <WakeOnLanPassword> port <Port> advertise <Advertise> lrxo <LargeReceiveOffload> ntf <NTupleFilter> ssbcs <StatisticsBlockCoalesceSec>
>pmctl link set-link dev ens37 alias ifalias desc configdevice mtub 10M bits 5G duplex full auton no wol phy,unicast,broadcast,multicast,arp,magic,secureon wolpassd cb:a9:87:65:43:21  port mii advertise 10baset-half,10baset-full,20000basemld2-full lrxo true ntf true ssbcs 1024

```

#### firewall nftable
```bash

# Add nft table.
pmctl network add-nft-table name <TABLE> family <FAMILY>
>pmctl network add-nft-table name test99 family inet

# Delete nft table.
pmctl network delete-nft-table name <TABLE> family <FAMILY>
>pmctl network delete-nft-table name test99 family inet

# Show nft table.
pmctl network show-nft-table name <TABLE> family <FAMILY>
>pmctl network show-nft-table name test99 family inet

# Show all nft tables.
>pmctl network show-nft-table

# Add nft chain.
pmctl network add-nft-chain name <CHAIN> table <TABLE> family <FAMILY> hook <HOOK> priority <PRIORITY> type <TYPE> policy <POLICY>
>pmctl network add-nft-chain name chain1 table test99 family inet hook input priority 300 type filter policy drop

# Delete nft chain.
pmctl network delete-nft-chain name <CHAIN> table <TABLE> family <FAMILY>
>pmctl network delete-nft-chain name chain1 table test99 family inet

# Show nft chain.
pmctl network show-nft-chain name <CHAIN> table <TABLE> family <FAMILY>
>pmctl network show-nft-chain name chain1 table test99 family inet

# Show all nft chain.
>pmctl network show-nft-chain

# Save all nft tables.
>pmctl network nft-save

# Run nft commands.
pmctl network nft-run <COMMAND>
>pmctl network nft-run nft add table inet test99
>pmctl network nft-run nft add chain inet test99 my_chain '{ type filter hook input priority 0; }'
>pmctl network nft-run nft add rule inet test99 my_chain tcp dport {telnet, http, https} accept
>pmctl network nft-run nft delete rule inet test99 my_chain handle 3
>pmctl network nft-run nft delete chain inet test99 my_chain
>pmctl network nft-run nft delete table inet test99

```

#### proc info and configuration
```bash

# Net device property stats.
pmctl status proc net path <PATH> property <PROPERTY>
pmctl status proc net path ipv6 property calipso_cache_bucket_size
                 Path: ipv6
             Property: calipso_cache_bucket_size
                Value: 10

# Net device property configuration.
pmctl proc net path <PATH> property <PROPERTY> value <VALUE>
>pmctl proc net path ipv6 property calipso_cache_bucket_size value 12

# Net device link property stats.
pmctl status proc net path <PATH> dev <LINK> property <PROPERTY>
>pmctl status proc net path ipv6 dev ens37 property mtu
                 Path: ipv6
                 Link: ens37
             Property: mtu
                Value: 1300

# Net device link property configuration.
pmctl proc net path <PATH> dev <LINK> property <PROPERTY> value <VALUE>
>pmctl proc net path ipv6 dev ens37 property mtu value 1500

# VM property stats.
pmctl status proc vm <PROPERTY>
>pmctl status proc vm page-cluster
             Property: page-cluster
                Value: 3

# VM property configuration.
>pmctl proc vm <PROPERTY> <VALUE>
pmctl proc vm page-cluster 5

# System property stats.
pmctl status proc system <PROPERTY>
>pmctl status proc system cpuinfo

# ARP stats.
pmctl status proc arp
>pmctl status proc arp
             IPAddress: 172.16.61.254
                HWType: 0x1
                 Flags: 0x2
             HWAddress: 00:50:56:f3:5d:48
                  Mask: *
                Device: ens37

             IPAddress: 172.16.61.254
                HWType: 0x1
                 Flags: 0x2
             HWAddress: 00:50:56:f3:5d:48
                  Mask: *
                Device: ens33

             IPAddress: 172.16.61.2
                HWType: 0x1
                 Flags: 0x2
             HWAddress: 00:50:56:f4:e7:22
                  Mask: *
                Device: ens33

             IPAddress: 172.16.61.2
                HWType: 0x1
                 Flags: 0x2
             HWAddress: 00:50:56:f4:e7:22
                  Mask: *
                Device: ens37
```

#### Netstat info

```bash
pmctl status proc netstat <PROTOCOL>
>pmctl status proc netstat tcp
```

#### Process stats
```bash
pmctl status proc process <PID> <PROPERTY>
>pmctl status proc process 88157 pid-memory-percent
```

#### Protopidstat stats
```bash
pmctl status proc protopidstat <PID> <PROTOCOL>
>pmctl status proc protopidstat 89502 tcp

```

#### Package Management
```bash
# List all packages
pmctl pkg list
> pmctl pkg list

# List specific packages
> pmctl pkg list <pkg>
pmctl pkg list lsof

# Info
> pmctl pkg info <pkg>
pmctl pkg info lsof

# Download metada
> pmctl pkg makecache
pmctl pkg makecache

# Clean cache
> pmctl pkg clean
pmctl pkg clean

# List repositories
> pmctl pkg repolist
pmctl pkg repolist

# Search packages
> pmctl pkg search <pattern>
pmctl pkg search lsof

# Get update info
> pmctl pkg updateinfo
> pmctl pkg updateinfo --list
> pmctl pkg updateinfo --info

# Install a package
> pmctl pkg install <pkg>
pmctl install lsof

# Update a package
> pmctl pkg update <pkg>
pmctl pkg update lsof

# Remove a package
> pmctl pkg remove <pkg>
pmctl pkg remove lsof

# Update all
> pmctl pkg update
pmctl pkg update

# Use common options
> pmctl pkg [--allowerasing][--best][--cacheonly][--config=<file>][--disablerepo=<pattern>[,..]]
	[--disableexcludes][--downloaddir=<dir>][--downloadonly][--enablerepo=<pattern>[,..]]
	[--exclude=<pkg>][--installroot=<dir>][--noautoremove][--nogpgcheck][--noplugins]
	[--rebootrequired][--refresh][--releaserver=<release>][--repoid=<repo>]
	[--repofrompath=<repo>,<dir>][--security][--secseverity=<sev>][--setopt=<key=value>[,..]]
	[--skipconflicts][--skipdigest][--skipobsletes][--skipsignature]
pmctl pkg --repoid=photon-debuginfo list lsof*
```

#### How to configure users ?

##### Unix domain socket

Any users added to the group photon-mgmt, they are allowed to access the unix socket.
```bash
# usermod -a -G photon-mgmt exampleusername
```

##### Web users via pmctl

Export the token key to the enviroment as below
```bash
❯ export PHOTON_MGMT_AUTH_TOKEN=secret
```

#### How to configure TLS ?

Generate private key (.key)

```bash
# Key considerations for algorithm "RSA" ≥ 2048-bit
$ openssl genrsa -out server.key 2048
Generating RSA private key, 2048 bit long modulus (2 primes)
.......................+++++
.+++++
e is 65537 (0x010001)

openssl genrsa -out server.key 2048
```

Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)

```bash
$ openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]:

```

Place ```server.crt``` and ```server.key``` in the dir ```/etc/photon-mgmt/tls```

```bash
[root@Zeus tls]# ls
server.crt  server.key
[root@Zeus tls]# pwd
/etc/photon-mgmt/cert

```

Use case: https

```bash
$ curl --header "X-Session-Token: secret" --request GET https://localhost:5208/api/v1/network/ethtool/vmnet8/get-link-features -k --tlsv1.2

```

#### How to write your own plugin ?

photon-mgmtd is designed with robust plugin based architecture in mind. You can always add and remove modules to it with minimal effort
You can implement and incorporate application features very quickly. Because plug-ins are separate modules with well-defined interfaces,
you can quickly isolate and solve problems. You can create custom versions of an application with minimal source code modifications.

* Choose namespace under `plugins` directory (systemd, system, proc) where you want to put your module.
* Write sub router see for example ```plugins/systemd/```
* Write your module ```module.go``` and  ```module_router.go```
* Write ```RegisterRouterModule```
* Register ```RegisterRouterModule``` with parent router for example for ```login``` registered with
  ```RegisterRouterSystem``` under ```system``` namespace as ```login.RegisterRouterLogin```
* See examples directory how to write on your own plugin.

### Todos

 - Write Tests
 - networkd

License
----

Apache 2.0
