#!/usr/bin/env python

import xml.dom.minidom
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-f', '--file', action = 'store', help = 'You must specify an nmap xml file to read from')
parser.add_argument('-n', '--nse', action = 'store', help = 'Search the nmap Script output for a particular nse')
parser.add_argument('-t', '--target', action = 'store', help = 'Search nmap results for a specific host')
parser.add_argument('-v', '--vulns', action = 'store_true', help = 'Search for Vulnerabilities identified by Nmap')
parser.add_argument('-l', '--list', action = 'store_true', help = 'List all identified nse\'s by Nmap')
parser.add_argument('-s', '--showcmd', action = 'store_true', help = 'Show a cmd that can be run to test the nse')

file = parser.parse_args().file
nse = parser.parse_args().nse
target_host = parser.parse_args().target
vulns = parser.parse_args().vulns
list = parser.parse_args().list
showcmd = parser.parse_args().showcmd
    
def portsTag(ip):
    ports = host.getElementsByTagName("port")
    for item in ports:
        port = item.getAttribute("portid")
        scripts = item.getElementsByTagName("script")
        for script in scripts:
            if nse:
                if nse in script.getAttribute("id"):
                    nseOutput(ip,port,script)
            elif vulns:
                if "VULNERABLE:" in script.getAttribute("output"):
                    nseOutput(ip,port,script)
            elif list:
                if script.getAttribute("id") not in nse_list:
                    nse_list.append(script.getAttribute("id"))
            else:
                nseOutput(ip,port,script)

def nseOutput(ip,port,script):
    print("\n#" + "========== " + script.getAttribute("id") + " ==========" + "#")
    print(str(ip) + ":" + str(port))
    if showcmd:
        print("\n# nmap -Pn -n --script=\"" + script.getAttribute("id") + "\" -p" + str(port) + " " + str(ip))
    print(script.getAttribute("output"))
    print("\n#" + "========== end " + script.getAttribute("id") + " ==========" + "#")

if file:
    doc = xml.dom.minidom.parse(file)
    nse_list = []
    for host in doc.getElementsByTagName("host"):
        addresses = host.getElementsByTagName("address")
        if target_host:
            if addresses[0].getAttribute("addr") == target_host:
                ip = target_host
                portsTag(ip)
        else:
            ip = addresses[0].getAttribute("addr")
            portsTag(ip)
    if list:
        nse_list.sort()
        print('\n'.join(nse_list))
