#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2020 VMware, Inc.

import os
import sys
import subprocess
import time
import shutil
import configparser
import collections
import unittest
from argparse import ArgumentParser
import pmd

sname = "localhost"
uname = "root"
passwd = " "

networkd_unit_file_path = '/etc/systemd/network'

units = ["10-test99.network",
         "10-test98.network",
         '10-test-99.network',
         "10-wlan1.network",
         "10-wlan0.network",
         '10-test98.network',
         '10-vlan-98.network',
         '10-vlan-98.netdev',
         '10-vlan-98.network',
         '10-vxlan-98.network',
         '10-vxlan-98.netdev',
         '10-bridge-98.netdev',
         '10-bridge-98.network',
         '10-bond-98.netdev',
         '10-bond-98.network',
         '10-macvlan-98.netdev',
         '10-macvlan-98.network',
         '10-macvtap-98.netdev',
         '10-macvtap-98.network',
         '10-ipvlan-98.netdev',
         '10-ipvlan-98.network',
         '10-ipvtap-98.netdev',
         '10-ipvtap-98.network',
         '10-vrf-98.netdev',
         '10-vrf-98.network',
         '10-veth-98.netdev',
         '10-veth-98.network',
         '10-ipip-98.netdev',
         '10-ipip-98.network',
         '10-sit-98.netdev',
         '10-sit-98.network',
         '10-gre-98.netdev',
         '10-gre-98.network',
         '10-vti-98.netdev',
         '10-vri-98.network',
         '10-wg99.netdev',
         '10-wg99.network']

def link_exits(link):
    return os.path.exists(os.path.join('/sys/class/net', link))

def link_remove(link):
    if os.path.exists(os.path.join('/sys/class/net', link)):
        subprocess.call(['ip', 'link', 'del', 'dev', link])

def link_add_dummy(link):
    subprocess.call(['ip', 'link', 'add', 'dev', link, 'type', 'dummy'])

def unit_exits(unit):
    return os.path.exists(os.path.join(networkd_unit_file_path, unit))

def remove_units_from_netword_unit_path():
    for i in units:
        if (os.path.exists(os.path.join(networkd_unit_file_path, i))):
            os.remove(os.path.join(networkd_unit_file_path, i))

def restart_networkd():
    subprocess.call(['systemctl', 'restart', 'systemd-networkd'])
    subprocess.check_call(['sleep', '5'])

class TestPYNetwork(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()

    def teardown_method(self):
        subprocess.check_call(['sleep', '5'])
        remove_units_from_netword_unit_path()
        link_remove('test99')
        subprocess.check_call(['sleep', '5'])

    def test_python3_get_version(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_version())"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, '0.4')
        self.teardown_method()

    def test_python3_is_networkd_running(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.is_networkd_running())"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'Running')
        self.teardown_method()

    def test_python3_get_status(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_system_status())"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'System Name')
        self.teardown_method()

    def test_python3_get_show_link(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_status(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'HWAddress')
        self.teardown_method()

    def test_python3_set_mtu(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-mtu\", \"test99\", \"1400\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MTUBytes') == '1400')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_mtu(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, '1400')
        self.teardown_method()

    def test_python3_set_mac(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-mac\", \"test99\", \"00:0c:29:3a:bc:11\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Link', 'MACAddress') == '00:0c:29:3a:bc:11')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_macaddr(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, '00:0c:29:3a:bc:11')
        self.teardown_method()

    def test_python3_set_hostname(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        result = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_hostname())"], stderr= subprocess.STDOUT)
        org_hostname = result.decode('utf-8').strip()
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-hostname\", \"photon-hostname-test\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_hostname())"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'photon-hostname-test')
        subprocess.check_call(['sleep', '1'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-hostname\", \""+org_hostname+"\")"])
        subprocess.check_call(['sleep', '1'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_hostname())"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, org_hostname)
        self.teardown_method()

    def test_python3_set_dhcp_type(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp-mode\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'DHCP') == 'yes')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_dhcp_mode(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'yes')
        self.teardown_method()

    def test_python3_set_dhcp_iaid(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp-mode\", \"test99\", \"ipv4\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp-iaid\", \"test99\", \"5555\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'IAID') == '5555')
        # TODO: Issue from NCM
        #output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_iaid(\"test99\"))"], universal_newlines=True).rstrip()
        #print(output)

        #self.assertRegex(output, '5555')
        self.teardown_method()

    def test_python3_add_static_address(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-link-address\", \"test99\", \"address\", \"192.168.1.45/24\", \"peer\", \
                               \"192.168.1.46/24\", \"dad\", \"ipv4\", \"scope\", \"link\", \"pref-lifetime\", \"forever\", \
                               \"prefix-route\", \"yes\", \"label\", \"3434\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')
        assert(parser.get('Address', 'Peer') == '192.168.1.46/24')
        assert(parser.get('Address', 'Scope') == 'link')
        assert(parser.get('Address', 'PreferredLifetime') == 'forever')
        assert(parser.get('Address', 'AddPrefixRoute') == 'yes')
        assert(parser.get('Address', 'DuplicateAddressDetection') == 'ipv4')
        assert(parser.get('Address', 'Label') == '3434')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_Addresses(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, '192.168.1.45/24')
        self.teardown_method()


    def test_python3_add_default_gateway(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-link-address\", \"test99\", \"address\", \"192.168.1.45/24\", \"peer\", \
                               \"192.168.1.46/24\", \"dad\", \"ipv4\", \"scope\", \"link\", \"pref-lifetime\", \"forever\", \
                               \"prefix-route\", \"yes\", \"label\", \"3434\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-default-gateway\", \"test99\", \"gw\", \"192.168.1.1\", \"onlink\", \"true\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1')
        assert(parser.get('Route', 'GatewayOnLink') == 'yes')
        self.teardown_method()

    def test_python3_add_route(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-link-address\", \"test99\", \"address\", \"192.168.1.45/24\", \"peer\", \
                               \"192.168.1.46/24\", \"dad\", \"ipv4\", \"scope\", \"link\", \"pref-lifetime\", \"forever\", \
                               \"prefix-route\", \"yes\", \"label\", \"3434\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Address', 'Address') == '192.168.1.45/24')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-route\", \"test99\", \"gw\", \"192.168.1.1\", \"dest\", \"192.168.1.2\", \"metric\", \"111\", \"scope\", \
                               \"link\", \"mtu\", \"1400\", \"table\", \"local\", \"proto\", \"static\", \"type\", \"unicast\", \"onlink\", \"yes\", \"ipv6-pref\", \
                               \"medium\", \"src\", \"192.168.1.4\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Route', 'Destination') == '192.168.1.2')
        assert(parser.get('Route', 'Gateway') == '192.168.1.1')
        assert(parser.get('Route', 'GatewayOnLink') == 'yes')
        assert(parser.get('Route', 'Metric') == '111')
        assert(parser.get('Route', 'MTUBytes') == '1400')
        assert(parser.get('Route', 'Protocol') == 'static')
        assert(parser.get('Route', 'Scope') == 'link')
        assert(parser.get('Route', 'Table') == 'local')
        assert(parser.get('Route', 'IPv6Preference') == 'medium')
        assert(parser.get('Route', 'Source') == '192.168.1.4')
        # TODO: Issue from NCM
        #subprocess.check_call(['sleep', '5'])
        #output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_Routes(\"test99\"))"], universal_newlines=True).rstrip()
        #print(output)

        #self.assertRegex(output, '10.10.10.10')
        self.teardown_method()

    def test_python3_add_routing_policy_rule(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-rule\", \"test99\", \"table\", \"10\", \"to\", \"192.168.1.2/24\", \"from\", \"192.168.1.3/24\", \
                               \"oif\", \"test99\", \"iif\", \"test99\", \"tos\", \"0x12\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('RoutingPolicyRule', 'Table') == '10')
        assert(parser.get('RoutingPolicyRule', 'From') == '192.168.1.3/24')
        assert(parser.get('RoutingPolicyRule', 'To') == '192.168.1.2/24')
        assert(parser.get('RoutingPolicyRule', 'TypeOfService') == '0x12')
        assert(parser.get('RoutingPolicyRule', 'OutgoingInterface') == 'test99')
        assert(parser.get('RoutingPolicyRule', 'IncomingInterface') == 'test99')
        self.teardown_method()

    def test_python3_add_dns(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '30'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-dns\", \"test99\", \"192.168.1.45\", \"192.168.1.46\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        subprocess.check_call(['sleep', '5'])
        #subprocess.check_call(['sleep', '5'])
        # output of this command depends if valid dns-server is set
        # thus ignoring the output of the command and just validating if command executes
        # successfully.
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_dns_servers())"], universal_newlines=True).rstrip()
        if output is None:
            assert(0)
        #print(output)
        #self.assertRegex(output, '192.168.1.45')
        #self.assertRegex(output, '192.168.1.46')
        self.teardown_method()

    def test_python3_add_domain(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-domain\", \"test99\", \"domain1\", \"domain2\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'Domains') == 'domain2 domain1')
        # TODO: Issue from NCM
        #subprocess.check_call(['sleep', '5'])
        #output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_dns_domains())"], universal_newlines=True).rstrip()
        #print(output)

        #self.assertRegex(output, 'domain1')
        #self.assertRegex(output, 'domain2')
        self.teardown_method()

    def test_python3_add_ntp(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-ntp\", \"test99\", \"192.168.1.34\", \"192.168.1.45\")"])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')
        subprocess.check_call(['sleep', '5'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_ntp_servers(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, '192.168.1.34')
        self.assertRegex(output, '192.168.1.45')
        self.teardown_method()

    def test_python3_set_ntp(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-ntp\", \"test99\", \"192.168.1.34\", \"192.168.1.45\")"])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')
        subprocess.check_call(['sleep', '5'])
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_ntp_servers(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, '192.168.1.34')
        self.assertRegex(output, '192.168.1.45')
        self.teardown_method()

    def test_python3_set_ip_v6_router_advertisement(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-ipv6acceptra\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv6AcceptRA') == 'true')
        self.teardown_method()

    def test_python3_set_link_local_addressing(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-local-address\", \"test99\", \"yes\")"])

        subprocess.check_call(['sleep', '5'])
        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LinkLocalAddressing') == 'true')
        self.teardown_method()

    def test_python3_set_ipv4_link_local_route(self):
        self.setup_method()
        assert(link_exits('test99') == True);

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-ipv4ll-route\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPv4LLRoute') == 'true')
        self.teardown_method()

    def test_python3_set_llmnr(self):
        self.setup_method()
        assert(link_exits('test99') == True);

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-llmnr\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLMNR') == 'true')
        self.teardown_method()

    def test_python3_set_multicast_dns(self):
        self.setup_method()
        assert(link_exits('test99') == True);

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-multicast-dns\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'MulticastDNS') == 'true')
        self.teardown_method()

    def test_python3_set_ip_masquerade(self):
        self.setup_method()
        assert(link_exits('test99') == True);

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-ipmasquerade\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'IPMasquerade') == 'true')
        self.teardown_method()


    def test_python3_set_dhcp4_client_identifier(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp4-client-identifier\", \"test99\", \"mac\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_link_dhcp4_client_identifier(\"test99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'mac')
        self.teardown_method()

    def test_python3_set_dhcp4_use_dns(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp4-use-dns\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseDNS') == 'true')
        self.teardown_method()

    def test_python3_set_dhcp4_use_mtu(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp4-use-mtu\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        self.teardown_method()

    def test_python3_set_dhcp4_use_domains(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp4-use-domains\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseDomains') == 'true')
        self.teardown_method()

    def test_python3_set_dhcp4_use_ntp(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp4-use-ntp\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseNTP') == 'true')
        self.teardown_method()

    def test_python3_set_dhcp4_use_routes(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-dhcp4-use-routes\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('DHCPv4', 'UseRoutes') == 'true')
        self.teardown_method()

    def test_python3_set_link_lldp(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-lldp\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'LLDP') == 'true')
        self.teardown_method()

    def test_python3_set_link_emit_lldp(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['sleep', '5'])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-emit-lldp\", \"test99\", \"yes\")"])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')
        assert(parser.get('Network', 'EmitLLDP') == 'true')
        self.teardown_method()

class TestPYNetDev(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def setup_method(self):
        link_remove('test98')
        link_add_dummy('test98')
        restart_networkd()

    def teardown_method(self):
        remove_units_from_netword_unit_path()
        link_remove('test98')

    def test_python3_create_vlan(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-vlan\", \"vlan-98\", \"dev\", \"test98\",  \"id\", \"11\")"])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-vlan-98.netdev') == True)
        assert(unit_exits('10-vlan-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '15'])

        assert(link_exits('vlan-98') == True)

        vlan_parser = configparser.ConfigParser()
        vlan_parser.read(os.path.join(networkd_unit_file_path, '10-vlan-98.netdev'))

        assert(vlan_parser.get('NetDev', 'Name') == 'vlan-98')
        assert(vlan_parser.get('NetDev', 'kind') == 'vlan')
        assert(vlan_parser.get('VLAN', 'id') == '11')

        vlan_network_parser = configparser.ConfigParser()
        vlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-vlan-98.network'))

        assert(vlan_network_parser.get('Match', 'Name') == 'vlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'VLAN') == 'vlan-98')

        link_remove('vlan-98')
        self.teardown_method()

    def test_python3_create_macvlan(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-macvlan\", \"macvlan-98\", \"dev\", \"test98\", \"mode\", \"private\")"])
        assert(unit_exits('10-macvlan-98.netdev') == True)
        assert(unit_exits('10-macvlan-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('macvlan-98') == True)

        macvlan_parser = configparser.ConfigParser()
        macvlan_parser.read(os.path.join(networkd_unit_file_path, '10-macvlan-98.netdev'))

        assert(macvlan_parser.get('NetDev', 'Name') == 'macvlan-98')
        assert(macvlan_parser.get('NetDev', 'kind') == 'macvlan')
        assert(macvlan_parser.get('MACVLAN', 'Mode') == 'private')

        macvlan_network_parser = configparser.ConfigParser()
        macvlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-macvlan-98.network'))

        assert(macvlan_network_parser.get('Match', 'Name') == 'macvlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'MACVLAN') == 'macvlan-98')

        link_remove('macvlan-98')
        self.teardown_method()

    def test_python3_create_macvtap(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-macvtap\", \"macvtap-98\", \"dev\", \"test98\", \"mode\", \"private\")"])
        assert(unit_exits('10-macvtap-98.netdev') == True)
        assert(unit_exits('10-macvtap-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('macvtap-98') == True)

        macvlan_parser = configparser.ConfigParser()
        macvlan_parser.read(os.path.join(networkd_unit_file_path, '10-macvtap-98.netdev'))

        assert(macvlan_parser.get('NetDev', 'Name') == 'macvtap-98')
        assert(macvlan_parser.get('NetDev', 'kind') == 'macvtap')
        assert(macvlan_parser.get('MACVTAP', 'Mode') == 'private')

        macvlan_network_parser = configparser.ConfigParser()
        macvlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-macvtap-98.network'))

        assert(macvlan_network_parser.get('Match', 'Name') == 'macvtap-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'MACVTAP') == 'macvtap-98')

        link_remove('macvtap-98')
        self.teardown_method()

    def test_python3_create_ipvlan(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-ipvlan\", \"ipvlan-98\", \"dev\", \"test98\", \"mode\", \"l2\")"])
        assert(unit_exits('10-ipvlan-98.netdev') == True)
        assert(unit_exits('10-ipvlan-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('ipvlan-98') == True)

        ipvlan_parser = configparser.ConfigParser()
        ipvlan_parser.read(os.path.join(networkd_unit_file_path, '10-ipvlan-98.netdev'))

        assert(ipvlan_parser.get('NetDev', 'Name') == 'ipvlan-98')
        assert(ipvlan_parser.get('NetDev', 'kind') == 'ipvlan')
        assert(ipvlan_parser.get('IPVLAN', 'Mode') == 'L2')

        ipvlan_network_parser = configparser.ConfigParser()
        ipvlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipvlan-98.network'))

        assert(ipvlan_network_parser.get('Match', 'Name') == 'ipvlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'IPVLAN') == 'ipvlan-98')

        link_remove('ipvlan-98')
        self.teardown_method()

    def test_python3_create_ipvtap(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-ipvtap\", \"ipvtap-98\", \"dev\", \"test98\", \"mode\", \"l2\")"])
        assert(unit_exits('10-ipvtap-98.netdev') == True)
        assert(unit_exits('10-ipvtap-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])
        # TODO: Fix it, systemd-networkd doesn't create this link
        #assert(link_exits('ipvtap-98') == True)

        ipvtap_parser = configparser.ConfigParser()
        ipvtap_parser.read(os.path.join(networkd_unit_file_path, '10-ipvtap-98.netdev'))

        assert(ipvtap_parser.get('NetDev', 'Name') == 'ipvtap-98')
        assert(ipvtap_parser.get('NetDev', 'kind') == 'ipvtap')
        assert(ipvtap_parser.get('IPVTAP', 'Mode') == 'L2')

        ipvtap_network_parser = configparser.ConfigParser()
        ipvtap_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipvtap-98.network'))

        assert(ipvtap_network_parser.get('Match', 'Name') == 'ipvtap-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'IPVTAP') == 'ipvtap-98')

        # TODO: Fix it, systemd-networkd doesn't create this link
        link_remove('ipvtap-98')
        self.teardown_method()

    def test_python3_create_vrf(self):
        self.setup_method()
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-vrf\", \"vrf-98\", \"table\", \"11\")"])
        assert(unit_exits('10-vrf-98.netdev') == True)
        assert(unit_exits('10-vrf-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('vrf-98') == True)

        vrf_parser = configparser.ConfigParser()
        vrf_parser.read(os.path.join(networkd_unit_file_path, '10-vrf-98.netdev'))

        assert(vrf_parser.get('NetDev', 'Name') == 'vrf-98')
        assert(vrf_parser.get('NetDev', 'kind') == 'vrf')
        assert(vrf_parser.get('VRF', 'Table') == '11')

        vrf_network_parser = configparser.ConfigParser()
        vrf_network_parser.read(os.path.join(networkd_unit_file_path, '10-vrf-98.network'))

        assert(vrf_network_parser.get('Match', 'Name') == 'vrf-98')

        link_remove('vrf-98')
        self.teardown_method()

    def test_python3_create_veth(self):
        self.setup_method()
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-veth\", \"veth-98\", \"peer\", \"veth-99\")"])
        assert(unit_exits('10-veth-98.netdev') == True)
        assert(unit_exits('10-veth-98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('veth-98') == True)
        assert(link_exits('veth-99') == True)

        vrf_parser = configparser.ConfigParser()
        vrf_parser.read(os.path.join(networkd_unit_file_path, '10-veth-98.netdev'))

        assert(vrf_parser.get('NetDev', 'Name') == 'veth-98')
        assert(vrf_parser.get('NetDev', 'kind') == 'veth')
        assert(vrf_parser.get('Peer', 'Name') == 'veth-99')

        vrf_network_parser = configparser.ConfigParser()
        vrf_network_parser.read(os.path.join(networkd_unit_file_path, '10-veth-98.network'))

        assert(vrf_network_parser.get('Match', 'Name') == 'veth-98')

        link_remove('veth-98')
        self.teardown_method()

    def test_python3_create_ipip(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-ipip\", \"ipip-98\", \"dev\", \"test98\", \"local\", \"192.168.1.2\", \"remote\", \"192.168.1.3\")"])
        assert(unit_exits('10-ipip-98.netdev') == True)
        assert(unit_exits('10-ipip-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('ipip-98') == True)

        ipip_parser = configparser.ConfigParser()
        ipip_parser.read(os.path.join(networkd_unit_file_path, '10-ipip-98.netdev'))

        assert(ipip_parser.get('NetDev', 'Name') == 'ipip-98')
        assert(ipip_parser.get('NetDev', 'kind') == 'ipip')
        assert(ipip_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(ipip_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        ipip_network_parser = configparser.ConfigParser()
        ipip_network_parser.read(os.path.join(networkd_unit_file_path, '10-ipip-98.network'))

        assert(ipip_network_parser.get('Match', 'Name') == 'ipip-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'ipip-98')

        link_remove('ipip-98')
        self.teardown_method()

    def test_python3_create_gre(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-gre\", \"gre-98\", \"dev\", \"test98\", \"local\", \"192.168.1.2\", \"remote\", \"192.168.1.3\")"])
        assert(unit_exits('10-gre-98.netdev') == True)
        assert(unit_exits('10-gre-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('gre-98') == True)

        gre_parser = configparser.ConfigParser()
        gre_parser.read(os.path.join(networkd_unit_file_path, '10-gre-98.netdev'))

        assert(gre_parser.get('NetDev', 'Name') == 'gre-98')
        assert(gre_parser.get('NetDev', 'kind') == 'gre')
        assert(gre_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(gre_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        gre_network_parser = configparser.ConfigParser()
        gre_network_parser.read(os.path.join(networkd_unit_file_path, '10-gre-98.network'))

        assert(gre_network_parser.get('Match', 'Name') == 'gre-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'gre-98')

        link_remove('gre-98')
        self.teardown_method()

    def test_python3_create_gre(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-gre\", \"gre-98\", \"dev\", \"test98\", \"local\", \"192.168.1.2\", \"remote\", \"192.168.1.3\")"])
        assert(unit_exits('10-gre-98.netdev') == True)
        assert(unit_exits('10-gre-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('gre-98') == True)

        gre_parser = configparser.ConfigParser()
        gre_parser.read(os.path.join(networkd_unit_file_path, '10-gre-98.netdev'))

        assert(gre_parser.get('NetDev', 'Name') == 'gre-98')
        assert(gre_parser.get('NetDev', 'kind') == 'gre')
        assert(gre_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(gre_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        gre_network_parser = configparser.ConfigParser()
        gre_network_parser.read(os.path.join(networkd_unit_file_path, '10-gre-98.network'))

        assert(gre_network_parser.get('Match', 'Name') == 'gre-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'gre-98')

        link_remove('gre-98')
        self.teardown_method()

    def test_python3_create_vti(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-vti\", \"vti-98\", \"dev\", \"test98\", \"local\", \"192.168.1.2\", \"remote\", \"192.168.1.3\")"])
        assert(unit_exits('10-vti-98.netdev') == True)
        assert(unit_exits('10-vti-98.network') == True)
        assert(unit_exits('10-test98.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '5'])

        assert(link_exits('vti-98') == True)

        vti_parser = configparser.ConfigParser()
        vti_parser.read(os.path.join(networkd_unit_file_path, '10-vti-98.netdev'))

        assert(vti_parser.get('NetDev', 'Name') == 'vti-98')
        assert(vti_parser.get('NetDev', 'kind') == 'vti')
        assert(vti_parser.get('Tunnel', 'Local') == '192.168.1.2')
        assert(vti_parser.get('Tunnel', 'Remote') == '192.168.1.3')

        vti_network_parser = configparser.ConfigParser()
        vti_network_parser.read(os.path.join(networkd_unit_file_path, '10-vti-98.network'))

        assert(vti_network_parser.get('Match', 'Name') == 'vti-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'Tunnel') == 'vti-98')

        link_remove('vti-98')
        self.teardown_method()

    @unittest.skip
    def test_python3_create_wireguard(self):
        self.setup_method()
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-wg\", \"wg99\", \"private-key\", \"EEGlnEPYJV//kbvvIqxKkQwOiS+UENyPncC4bF46ong=\", \"listen-port\", \"32\", \"public-key\", \"RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA\", \"endpoint\", \"192.168.3.56:2000\", \"allowed-ips\", \"192.168.1.2\")"])

        assert(unit_exits('10-wg99.netdev') == True)
        assert(unit_exits('10-wg99.network') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '15'])

        assert(link_exits('wg99') == True)

        wg_parser = configparser.ConfigParser()
        wg_parser.read(os.path.join(networkd_unit_file_path, '10-wg99.netdev'))

        assert(wg_parser.get('NetDev', 'Name') == 'wg99')
        assert(wg_parser.get('NetDev', 'kind') == 'wireguard')
        assert(wg_parser.get('WireGuard', 'PrivateKey') == 'EEGlnEPYJV//kbvvIqxKkQwOiS+UENyPncC4bF46ong=')
        assert(wg_parser.get('WireGuard', 'ListenPort') == '32')
        assert(wg_parser.get('WireGuardPeer', 'PublicKey') == 'RDf+LSpeEre7YEIKaxg+wbpsNV7du+ktR99uBEtIiCA')
        assert(wg_parser.get('WireGuardPeer', 'Endpoint') == '192.168.3.56:2000')
        assert(wg_parser.get('WireGuardPeer', 'AllowedIPs') == '192.168.1.2')

        network_parser = configparser.ConfigParser()
        network_parser.read(os.path.join(networkd_unit_file_path, '10-wg99.network'))

        assert(network_parser.get('Match', 'Name') == 'wg99')

        link_remove('wg99')
        self.teardown_method()

    def test_python3_create_vxlan(self):
        self.setup_method()
        assert(link_exits('test98') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-vxlan\", \"vxlan-98\", \"dev\", \"test98\", \"vni\", \"32\", \"local\", \"192.168.1.2\", \"remote\", \"192.168.1.3\", \"port\", \"7777\")"])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-vxlan-98.network') == True)
        assert(unit_exits('10-vxlan-98.netdev') == True)

        restart_networkd()
        subprocess.check_call(['sleep', '15'])

        assert(link_exits('vxlan-98') == True)

        vxlan_parser = configparser.ConfigParser()
        vxlan_parser.read(os.path.join(networkd_unit_file_path, '10-vxlan-98.netdev'))

        assert(vxlan_parser.get('NetDev', 'Name') == 'vxlan-98')
        assert(vxlan_parser.get('NetDev', 'kind') == 'vxlan')
        assert(vxlan_parser.get('VXLAN', 'VNI') == '32')
        assert(vxlan_parser.get('VXLAN', 'Local') == '192.168.1.2')
        assert(vxlan_parser.get('VXLAN', 'Remote') == '192.168.1.3')
        assert(vxlan_parser.get('VXLAN', 'DestinationPort') == '7777')

        vxlan_network_parser = configparser.ConfigParser()
        vxlan_network_parser.read(os.path.join(networkd_unit_file_path, '10-vxlan-98.network'))

        assert(vxlan_network_parser.get('Match', 'Name') == 'vxlan-98')

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(parser.get('Match', 'Name') == 'test98')
        assert(parser.get('Network', 'VXLAN') == 'vxlan-98')

        link_remove('vxlan-98')
        self.teardown_method()

    def test_python3_create_bridge(self):
        self.setup_method()
        link_add_dummy('test-99')
        assert(link_exits('test98') == True)
        assert(link_exits('test-99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-bridge\", \"bridge-98\", \"test98\", \"test-99\")"])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-test-99.network') == True)
        assert(unit_exits('10-bridge-98.network') == True)
        assert(unit_exits('10-bridge-98.netdev') == True)

        subprocess.check_call(['sleep', '5'])

        assert(link_exits('bridge-98') == True)

        bridge_parser = configparser.ConfigParser()
        bridge_parser.read(os.path.join(networkd_unit_file_path, '10-bridge-98.netdev'))

        assert(bridge_parser.get('NetDev', 'Name') == 'bridge-98')
        assert(bridge_parser.get('NetDev', 'kind') == 'bridge')

        bridge_network_parser = configparser.ConfigParser()
        bridge_network_parser.read(os.path.join(networkd_unit_file_path, '10-bridge-98.network'))

        assert(bridge_network_parser.get('Match', 'Name') == 'bridge-98')

        test98_parser = configparser.ConfigParser()
        test98_parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(test98_parser.get('Match', 'Name') == 'test98')
        assert(test98_parser.get('Network', 'Bridge') == 'bridge-98')

        test99_parser = configparser.ConfigParser()
        test99_parser.read(os.path.join(networkd_unit_file_path, '10-test-99.network'))

        assert(test99_parser.get('Match', 'Name') == 'test-99')
        assert(test99_parser.get('Network', 'Bridge') == 'bridge-98')

        link_remove('bridge-98')
        link_remove('test-99')
        self.teardown_method()

    def test_python3_create_bond(self):
        self.setup_method()
        link_add_dummy('test-99')
        assert(link_exits('test98') == True)
        assert(link_exits('test-99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"create-bond\", \"bond-98\", \"mode\", \"balance-rr\", \"test98\", \"test-99\")"])
        assert(unit_exits('10-test98.network') == True)
        assert(unit_exits('10-test-99.network') == True)
        assert(unit_exits('10-bond-98.network') == True)
        assert(unit_exits('10-bond-98.netdev') == True)

        subprocess.check_call(['sleep', '5'])

        assert(link_exits('bond-98') == True)

        bond_parser = configparser.ConfigParser()
        bond_parser.read(os.path.join(networkd_unit_file_path, '10-bond-98.netdev'))

        assert(bond_parser.get('NetDev', 'Name') == 'bond-98')
        assert(bond_parser.get('NetDev', 'kind') == 'bond')
        assert(bond_parser.get('Bond', 'Mode') == 'balance-rr')

        bond_network_parser = configparser.ConfigParser()
        bond_network_parser.read(os.path.join(networkd_unit_file_path, '10-bond-98.network'))

        assert(bond_network_parser.get('Match', 'Name') == 'bond-98')

        test98_parser = configparser.ConfigParser()
        test98_parser.read(os.path.join(networkd_unit_file_path, '10-test98.network'))

        assert(test98_parser.get('Match', 'Name') == 'test98')
        assert(test98_parser.get('Network', 'Bond') == 'bond-98')

        test99_parser = configparser.ConfigParser()
        test99_parser.read(os.path.join(networkd_unit_file_path, '10-test-99.network'))

        assert(test99_parser.get('Match', 'Name') == 'test-99')
        assert(test99_parser.get('Network', 'Bond') == 'bond-98')

        link_remove('bond-98')
        link_remove('test-99')
        self.teardown_method()

class TestNFTable(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def teardown_method(self):
        subprocess.call(['nft', 'delete', 'table', 'testtable99'])

    def test_python3_add_table(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])

        output = subprocess.check_output(['nft', 'list', 'tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'table ip testtable99')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_tables(\"ipv4\", \"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'testtable99')
        self.teardown_method()

    def test_python3_delete_table(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])

        output = subprocess.check_output(['nft', 'list', 'tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'table ip testtable99')
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"delete-nft-table\", \"ipv4\", \"testtable99\")"])

        output = subprocess.check_output(['nft', 'list', 'tables'], universal_newlines=True).rstrip()
        print(output)

        self.assertNotRegex(output, 'table ip testtable99')

    def test_python3_add_chain(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')
        self.teardown_method()

    def test_python3_delete_chain(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"delete-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertNotRegex(output, 'testchain99')
        self.teardown_method()

    def test_python3_add_rule_tcp_accept(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"tcp\", \"dport\", \"9999\", \"accept\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp dport 9999 counter packets 0 bytes 0 accept')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'tcp dport 9999 counter packets 0 bytes 0 accept')
        self.teardown_method()

    def test_python3_add_rule_tcp_drop(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"tcp\", \"dport\", \"9999\", \"drop\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp dport 9999 counter packets 0 bytes 0 drop')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'tcp dport 9999 counter packets 0 bytes 0 drop')
        self.teardown_method()

    def test_python3_add_rule_tcp_drop_sport(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"tcp\", \"sport\", \"9999\", \"drop\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp sport 9999 counter packets 0 bytes 0 drop')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'tcp sport 9999 counter packets 0 bytes 0 drop')
        self.teardown_method()

    def test_python3_add_rule_tcp_drop_accept_sport(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"tcp\", \"sport\", \"9999\", \"accept\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'tcp sport 9999 counter packets 0 bytes 0 accept')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'tcp sport 9999 counter packets 0 bytes 0 accept')
        self.teardown_method()

    def test_python3_add_rule_udp_accept_sport(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"udp\", \"sport\", \"9999\", \"accept\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp sport 9999 counter packets 0 bytes 0 accept')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'udp sport 9999 counter packets 0 bytes 0 accept')
        self.teardown_method()

    def test_python3_add_rule_udp_drop_dport(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"udp\", \"dport\", \"9999\", \"drop\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 drop')
        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 drop')
        self.teardown_method()

    def test_python3_add_rule_udp_accept_dport(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"udp\", \"dport\", \"9999\", \"accept\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_rules(\"testtable99\"))"], universal_newlines=True).rstrip()
        print(output)
        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')
        self.teardown_method()

    def test_python3_delete_rule(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-table\", \"ipv4\", \"testtable99\")"])
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-chain\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['python3', '-c', self.prefix+"print(p.get_nft_chains(\"ipv4\", \"testtable99\", \"testchain99\"))"], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'testtable99')
        self.assertRegex(output, 'testchain99')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\", \"udp\", \"dport\", \"9999\", \"accept\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)

        self.assertRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"delete-nft-rule\", \"ipv4\", \"testtable99\", \"testchain99\")"])

        output = subprocess.check_output(['nft', 'list', 'table', 'testtable99'], universal_newlines=True).rstrip()
        print(output)
        self.assertNotRegex(output, 'udp dport 9999 counter packets 0 bytes 0 accept')
        self.teardown_method()

class TestPYDHCPv4Server(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()
        subprocess.check_call(['sleep', '3'])

    def teardown_method(self):
        subprocess.check_call(['sleep', '3'])
        remove_units_from_netword_unit_path()
        subprocess.check_call(['sleep', '1'])
        link_remove('test99')

    def test_python3_configure_dhcpv4_server(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-dhcpv4-server\", \"test99\", \"pool-offset\", \
                               \"10\", \"pool-size\", \"20\", \"default-lease-time\", \"100\", \
                               \"max-lease-time\", \"200\", \"emit-dns\", \"yes\", \"dns\", \"192.168.1.1\", \
                               \"emit-router\", \"yes\")"])

        subprocess.check_call(['sleep', '3'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('Network', 'DHCPServer') == 'yes')

        assert(parser.get('DHCPServer', 'PoolOffset') == '10')
        assert(parser.get('DHCPServer', 'PoolSize') == '20')
        assert(parser.get('DHCPServer', 'DefaultLeaseTimeSec') == '100')
        assert(parser.get('DHCPServer', 'MaxLeaseTimeSec') == '200')
        assert(parser.get('DHCPServer', 'EmitDNS') == 'yes')
        assert(parser.get('DHCPServer', 'DNS') == '192.168.1.1')
        assert(parser.get('DHCPServer', 'EmitRouter') == 'yes')
        self.teardown_method()

class TestPYIPv6RA(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def setup_method(self):
        link_remove('test99')
        link_add_dummy('test99')
        restart_networkd()
        subprocess.check_call(['sleep', '3'])

    def teardown_method(self):
        subprocess.check_call(['sleep', '3'])
        remove_units_from_netword_unit_path()
        subprocess.check_call(['sleep', '1'])
        link_remove('test99')

    def test_python3_configure_ipv6ra(self):
        self.setup_method()
        assert(link_exits('test99') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
        assert(unit_exits('10-test99.network') == True)

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-ipv6ra\", \"test99\", \"prefix\", \"2002:da8:1:0::/64\", \
                               \"pref-lifetime\", \"100\", \"valid-lifetime\", \"200\", \"assign\", \"yes\", \
                               \"managed\", \"yes\", \"emit-dns\", \"yes\", \"dns\", \"2002:da8:1:0::1\", \
                               \"domain\", \"test.com\", \"emit-domain\", \"yes\", \"dns-lifetime\", \"100\", \"router-pref\", \"medium\", \
                               \"route-prefix\", \"2001:db1:fff::/64\", \"route-lifetime\", \"1000\")"])

        subprocess.check_call(['sleep', '3'])

        parser = configparser.ConfigParser()
        parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

        assert(parser.get('Match', 'Name') == 'test99')

        assert(parser.get('Network', 'IPv6SendRA') == 'yes')

        assert(parser.get('IPv6Prefix', 'Prefix') == '2002:da8:1::/64')
        assert(parser.get('IPv6Prefix', 'PreferredLifetimeSec') == '100')
        assert(parser.get('IPv6Prefix', 'ValidLifetimeSec') == '200')

        assert(parser.get('IPv6SendRA', 'RouterPreference') == 'medium')
        assert(parser.get('IPv6SendRA', 'DNS') == '2002:da8:1::1')
        assert(parser.get('IPv6SendRA', 'EmitDNS') == 'yes')
        assert(parser.get('IPv6SendRA', 'Assign') == 'yes')
        assert(parser.get('IPv6SendRA', 'DNSLifetimeSec') == '100')
        assert(parser.get('IPv6SendRA', 'Domains') == 'test.com')

        assert(parser.get('IPv6RoutePrefix', 'LifetimeSec') == '1000')
        assert(parser.get('IPv6RoutePrefix', 'Route') == '2001:db1:fff::/64')
        self.teardown_method()

class TestPYGlobalDNSDomain(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def test_python3_configure_global_dns_server(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-dns\", \"global\", \"8.8.4.4\", \"8.8.8.8\", \"8.8.8.1\", \"8.8.8.2\")"])

        subprocess.check_call(['sleep', '3'])

        parser = configparser.ConfigParser()
        parser.read('/etc/systemd/resolved.conf')

        assert(parser.get('Resolve', 'DNS') == '8.8.4.4 8.8.8.1 8.8.8.2 8.8.8.8')

    def test_python3_configure_global_domain_server(self):
        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"add-domain\", \"global\", \"test1\", \"test2\")"])

        subprocess.check_call(['sleep', '3'])

        parser = configparser.ConfigParser()
        parser.read('/etc/systemd/resolved.conf')

        assert(parser.get('Resolve', 'Domains') == 'test1 test2')

class TestPYNetworkProxy(unittest.TestCase):
    def setUp(self):
        global sname
        global uname
        global passwd
        self.prefix = "import pmd;server = pmd.server(\""+sname+"\",\""+uname+"\",\""+passwd+"\"); p = server.net; "

    def test_python3_configure_network_proxy(self):

        if not os.path.exists("/etc/sysconfig/"):
                os.mkdir("/etc/sysconfig/")

        f = open("/etc/sysconfig/proxy", "w")
        f.write("PROXY_ENABLED=\"no\"\nHTTP_PROXY=""\nHTTPS_PROXY=""\nNO_PROXY=\"localhost, 127.0.0.1\"\n")
        f.close()

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-proxy\", \"enable\", \"yes\", \"http\", \"http://test.com:123\", \"https\", \"https://test.com:123\")"])

        dictionary = {}
        file = open("/etc/sysconfig/proxy")

        lines = file.read().split('\n')

        for line in lines:
            if line == '':
                 continue
            pair = line.split('=')
            dictionary[pair[0].strip('\'\'\"\"')] = pair[1].strip('\'\'\"\"')

        assert(dictionary["HTTP_PROXY"] == "http://test.com:123")
        assert(dictionary["HTTPS_PROXY"] == "https://test.com:123")
        assert(dictionary["PROXY_ENABLED"] == "yes")

        subprocess.check_call(['python3', '-c', self.prefix+"p.configure(\"set-proxy\", \"enable\", \"yes\", \"http\", \"http://test.com:123\", \"ftp\", \"https://test.com123\")"])

def main():
    global sname
    global uname
    global passwd
    parser = ArgumentParser()
    parser.add_argument("-s", "--servername", dest="server_name", default="localhost")
    parser.add_argument("-u", "--user", dest="user_name", default="root")
    parser.add_argument("-p", "--password", dest="password", default=" ")
    options = parser.parse_args()

    sname = options.server_name
    uname = options.user_name
    passwd = options.password
    unittest.main(argv=["ignored"], verbosity=2, exit=False)

if __name__ == "__main__": main()
