#!/usr/bin/python
import xml.etree.ElementTree as etree
import fnmatch
import os
import socket
import datetime
import sys


class Netcat:
    def __init__(self, ip, port):
        self.buff = ""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((ip, port))

    def write(self, data):
        self.socket.send(data)

    def close(self):
        self.socket.close()


matches = []
nc = Netcat(sys.argv[2].split(':')[0], int(sys.argv[2].split(':')[1]))

for root, dirnames, filenames in os.walk(sys.argv[1]):
    for filename in fnmatch.filter(filenames, '*.nessus*'):
        matches.append(os.path.join(root, filename))

for fn in matches:
    xml_content = open(fn, 'r').read()
    vulnerabilities = dict()
    single_params = ["agent", "cvss3_base_score", "cvss3_temporal_score", "cvss3_temporal_vector", "cvss3_vector",
                     "cvss_base_score", "cvss_temporal_score", "cvss_temporal_vector", "cvss_vector", "description",
                     "exploit_available", "exploitability_ease", "exploited_by_nessus", "fname", "in_the_news",
                     "patch_publication_date", "plugin_modification_date", "plugin_name", "plugin_output",
                     "plugin_publication_date", "plugin_type", "script_version", "see_also", "solution", "synopsis",
                     "vuln_publication_date"]
    root = etree.fromstring(xml_content)
    l = []
    for block in root:
        if block.tag == "Report":
            for report_host in block:
                host_properties_dict = dict()
                for report_item in report_host:
                    if report_item.tag == "HostProperties":
                        for host_properties in report_item:
                            host_properties_dict[host_properties.attrib['name']] = host_properties.text
                for report_item in report_host:
                    if 'pluginName' in report_item.attrib:
                        vulnerabilities = dict()
                        vulnerabilities['port'] = report_item.attrib['port']
                        vulnerabilities['pluginName'] = report_item.attrib['pluginName']
                        vulnerabilities['pluginFamily'] = report_item.attrib['pluginFamily']
                        vulnerabilities['pluginID'] = report_item.attrib['pluginID']
                        for param in report_item:
                            if param.tag == "risk_factor":
                                risk_factor = param.text
                                vulnerabilities['host'] = report_host.attrib['name']
                                vulnerabilities['riskFactor'] = risk_factor
                            else:
                                if not param.tag in single_params:
                                    if not param.tag in vulnerabilities:
                                        vulnerabilities[param.tag] = param.text

                                else:
                                    vulnerabilities[param.tag] = param.text
                        for param in host_properties_dict:
                            vulnerabilities[param] = host_properties_dict[param]
                        l.append(vulnerabilities)

    for vuln in l:
        vuln_str = "import_time=" + str(datetime.datetime.now()) + ';'
        for i, key in enumerate(vuln):
            lastitem= len(vuln) - 1
            if i == lastitem:
                vuln_str+= key + '=' + vuln[key].replace('\n', ' ')
            else:
                vuln_str += key + '=' + vuln[key].replace('\n', ' ') + ';'
        nc.write(vuln_str + '\r\n')
        print vuln_str
        
