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

prefix = ""

networkd_unit_file_path = '/etc/systemd/network'

units = ["10-test99.network"]

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

def setup_method():
    link_remove('test99')
    link_add_dummy('test99')
    restart_networkd()

def teardown_method():
    subprocess.check_call(['sleep', '5'])
    remove_units_from_netword_unit_path()
    link_remove('test99')
    subprocess.check_call(['sleep', '5'])

def test_python3_get_version():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_version())", '|', 'grep', '0.1'])

def test_python3_is_networkd_running():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.is_networkd_running())", '|', 'grep', 'Running'])

def test_python3_get_mtu():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_link_mtu(\"test99\"))", '|', 'grep', '1400'])

def test_python3_set_mtu():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-mtu\", \"test99\", \"1400\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Link', 'MTUBytes') == '1400')
    #result = subprocess.check_output(['cat', os.path.join(networkd_unit_file_path, '10-test99.network')], stderr= subprocess.STDOUT)
    #print(result.decode('utf-8').strip())
    #parser.read(result.decode('utf-8').strip())
    #assert(parser.get('Match', 'Name') == 'test99')
    #assert(parser.get('Link', 'MTUBytes') == '1400')
    test_python3_get_mtu()

def test_python3_set_mac():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-mac\", \"test99\", \"00:0c:29:3a:bc:11\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Link', 'MACAddress') == '00:0c:29:3a:bc:11')
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_link_macaddr(\"test99\"))", '|', 'grep', '00:0c:29:3a:bc:11'])

def test_python3_set_hostname():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    result = subprocess.check_output(['python3', '-c', prefix+"print(p.get_hostname())"], stderr= subprocess.STDOUT)
    org_hostname = result.decode('utf-8').strip()
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-hostname\", \"photon-hostname-test\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_hostname())", '|', 'grep', 'photon-hostname-test'])
    subprocess.check_call(['sleep', '1'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-hostname\", \""+org_hostname+"\")"])
    subprocess.check_call(['sleep', '1'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_hostname())", '|', 'grep', org_hostname])

def test_python3_set_dhcp_type():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp-mode\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'DHCP') == 'yes')
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_dhcp_mode(\"test99\"))", '|', 'grep', 'yes'])

def test_python3_set_dhcp_iaid():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp-mode\", \"test99\", \"ipv4\")"])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp-iaid\", \"test99\", \"5555\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('DHCP', 'IAID') == '5555')
    # TODO: Issue from NCM
    #subprocess.check_call(['python3', '-c', prefix+"print(p.get_link_iaid(\"test99\"))", '|', 'grep', '5555'])

def test_python3_add_static_address():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-link-address\", \"test99\", \"192.168.1.45/24\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Address', 'Address') == '192.168.1.45/24')
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_link_Addresses(\"test99\"))", '|', 'grep', '192.168.1.45/24'])


def test_python3_add_default_gateway():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-link-address\", \"test99\", \"192.168.1.45/24\")"])
    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Address', 'Address') == '192.168.1.45/24')

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-state\", \"test99\", \"up\")"])

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-default-gateway\", \"test99\", \"192.168.1.1\", \"onlink\", \"true\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Route', 'Gateway') == '192.168.1.1')

def test_python3_add_route():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-link-address\", \"test99\", \"192.168.1.45/24\")"])
    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Address', 'Address') == '192.168.1.45/24')

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-route\", \"test99\", \"10.10.10.10\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Route', 'Destination') == '10.10.10.10')
    # TODO: Issue from NCM
    #subprocess.check_call(['sleep', '5'])
    #subprocess.check_call(['python3', '-c', prefix+"print(p.get_link_Routes(\"test99\"))", '|', 'grep', '10.10.10.10'])

def test_python3_add_dns():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '30'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-dns\", \"test99\", \"192.168.1.45\", \"192.168.1.46\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_dns_servers())", '|', 'grep', '192.168.1.45'])
    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_dns_servers())", '|', 'grep', '192.168.1.46'])
    subprocess.check_call(['sleep', '5'])

def test_python3_add_domain():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-domain\", \"test99\", \"domain1\", \"domain2\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'Domains') == 'domain2 domain1')
    # TODO: Issue from NCM
    #subprocess.check_call(['sleep', '5'])
    #subprocess.check_call(['python3', '-c', prefix+"print(p.get_dns_domains())", '|', 'grep', 'domain1'])
    #subprocess.check_call(['sleep', '5'])
    #subprocess.check_call(['python3', '-c', prefix+"print(p.get_dns_domains())", '|', 'grep', 'domain2'])

def test_python3_add_ntp():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"add-ntp\", \"test99\", \"192.168.1.34\", \"192.168.1.45\")"])
    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')
    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_ntp_servers(\"test99\"))", '|', 'grep', '192.168.1.34'])
    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_ntp_servers(\"test99\"))", '|', 'grep', '192.168.1.45'])

def test_python3_set_ntp():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-ntp\", \"test99\", \"192.168.1.34\", \"192.168.1.45\")"])
    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'NTP') == '192.168.1.45 192.168.1.34')
    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_ntp_servers(\"test99\"))", '|', 'grep', '192.168.1.34'])
    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"print(p.get_ntp_servers(\"test99\"))", '|', 'grep', '192.168.1.45'])

def test_python3_set_ip_v6_router_advertisement():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-ipv6acceptra\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'IPv6AcceptRA') == 'true')

def test_python3_set_link_local_addressing():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-local-address\", \"test99\", \"yes\")"])

    subprocess.check_call(['sleep', '5'])
    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'LinkLocalAddressing') == 'true')

def test_python3_set_ipv4_link_local_route():
    assert(link_exits('test99') == True);

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-ipv4ll-route\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'IPv4LLRoute') == 'true')

def test_python3_set_llmnr():
    assert(link_exits('test99') == True);

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-llmnr\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'LLMNR') == 'true')

def test_python3_set_multicast_dns():
    assert(link_exits('test99') == True);

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-multicast-dns\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'MulticastDNS') == 'true')

def test_python3_set_ip_masquerade():
    assert(link_exits('test99') == True);

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-ipmasquerade\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'IPMasquerade') == 'true')


def test_python3_set_dhcp4_client_identifier():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp4-client-identifier\", \"test99\", \"mac\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('DHCPv4', 'ClientIdentifier') == 'mac')

def test_python3_set_dhcp4_use_dns():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp4-use-dns\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('DHCPv4', 'UseDNS') == 'true')

def test_python3_set_dhcp4_use_mtu():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp4-use-mtu\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')

def test_python3_set_dhcp4_use_domains():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp4-use-domains\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('DHCPv4', 'UseDomains') == 'true')

def test_python3_set_dhcp4_use_ntp():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp4-use-ntp\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('DHCPv4', 'UseNTP') == 'true')

def test_python3_set_dhcp4_use_routes():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-dhcp4-use-routes\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('DHCPv4', 'UseRoutes') == 'true')

def test_python3_set_link_lldp():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-lldp\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'LLDP') == 'true')

def test_python3_set_link_emit_lldp():
    assert(link_exits('test99') == True)

    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-link-mode\", \"test99\", \"yes\")"])
    assert(unit_exits('10-test99.network') == True)

    subprocess.check_call(['sleep', '5'])
    subprocess.check_call(['python3', '-c', prefix+"p.configure(\"set-emit-lldp\", \"test99\", \"yes\")"])

    parser = configparser.ConfigParser()
    parser.read(os.path.join(networkd_unit_file_path, '10-test99.network'))

    assert(parser.get('Match', 'Name') == 'test99')
    assert(parser.get('Network', 'EmitLLDP') == 'true')

def main():
    teardown_method()
    print("test_python3_get_version")
    setup_method()
    test_python3_get_version()
    teardown_method()
    print("test_python3_is_networkd_running")
    setup_method()
    test_python3_is_networkd_running()
    teardown_method()
    print("test_python3_set_mtu")
    setup_method()
    test_python3_set_mtu()
    teardown_method()
    print("test_python3_set_mac")
    setup_method()
    test_python3_set_mac()
    teardown_method()
    print("test_python3_set_hostname")
    setup_method()
    test_python3_set_hostname()
    teardown_method()
    print("test_python3_set_dhcp_type")
    setup_method()
    test_python3_set_dhcp_type()
    teardown_method()
    print("test_python3_set_dhcp_iaid")
    setup_method()
    test_python3_set_dhcp_iaid()
    teardown_method()
    print("test_python3_add_static_address")
    setup_method()
    test_python3_add_static_address()
    teardown_method()
    print("test_python3_add_default_gateway")
    setup_method()
    test_python3_add_default_gateway()
    teardown_method()
    print("test_python3_add_route")
    setup_method()
    test_python3_add_route()
    teardown_method()
    print("test_python3_add_dns")
    setup_method()
    test_python3_add_dns()
    teardown_method()
    print("test_python3_add_domain")
    setup_method()
    test_python3_add_domain()
    teardown_method()
    print("test_python3_add_ntp")
    setup_method()
    test_python3_add_ntp()
    teardown_method()
    print("test_python3_set_ntp")
    setup_method()
    test_python3_set_ntp()
    teardown_method()
    print("test_python3_set_ip_v6_router_advertisement")
    setup_method()
    test_python3_set_ip_v6_router_advertisement()
    teardown_method()
    print("test_python3_set_link_local_addressing")
    setup_method()
    test_python3_set_link_local_addressing()
    teardown_method()
    print("test_python3_set_ipv4_link_local_route")
    setup_method()
    test_python3_set_ipv4_link_local_route()
    teardown_method()
    print("test_python3_set_llmnr")
    setup_method()
    test_python3_set_llmnr()
    teardown_method()
    print("test_python3_set_multicast_dns")
    setup_method()
    test_python3_set_multicast_dns()
    teardown_method()
    print("test_python3_set_ip_masquerade")
    setup_method()
    test_python3_set_ip_masquerade()
    teardown_method()
    print("test_python3_set_dhcp4_client_identifier")
    setup_method()
    test_python3_set_dhcp4_client_identifier()
    teardown_method()
    print("test_python3_set_dhcp4_use_dns")
    setup_method()
    test_python3_set_dhcp4_use_dns()
    teardown_method()
    print("test_python3_set_dhcp4_use_mtu")
    setup_method()
    test_python3_set_dhcp4_use_mtu()
    teardown_method()
    print("test_python3_set_dhcp4_use_domains")
    setup_method()
    test_python3_set_dhcp4_use_domains()
    teardown_method()
    print("test_python3_set_dhcp4_use_ntp")
    setup_method()
    test_python3_set_dhcp4_use_ntp()
    teardown_method()
    print("test_python3_set_dhcp4_use_routes")
    setup_method()
    test_python3_set_dhcp4_use_routes()
    teardown_method()
    print("test_python3_set_link_lldp")
    setup_method()
    test_python3_set_link_lldp()
    teardown_method()
    print("test_python3_set_link_emit_lldp")
    setup_method()
    test_python3_set_link_emit_lldp()
    teardown_method()

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-s", "--servername", dest="server_name", default="localhost")
    parser.add_argument("-u", "--user", dest="user_name", default="root")
    parser.add_argument("-p", "--password", dest="password", default="")
    options = parser.parse_args()

    prefix = "import pmd;server = pmd.server(\""+options.server_name+"\",\""+options.user_name+"\",\""+options.password+"\"); p = server.net; "
    main()
