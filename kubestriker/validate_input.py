import re
import ipaddress
import yaml
from pathlib import Path

class ValidateInput(object):
    def __init__(self):
        pass

    def cidr_to_iplist(self, input):
        ip_list = list(ipaddress.ip_network(input, False).hosts())
        return ip_list

    '''Return IPs in IPv4 range, inclusive.'''
    def range_to_ip_list(self, beginning_ip, ending_ip):
        start_int = int(ipaddress.ip_address(beginning_ip).packed.hex(), 16)
        end_int = int(ipaddress.ip_address(ending_ip).packed.hex(), 16)
        return [ipaddress.ip_address(ip).exploded for ip in range(start_int, end_int + 1)]


    def iprange_to_iplist(self, input_range):
        input = input_range.strip()
        span_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The beginning IP Address
                                     \s*-\s*
                                     (\d{1,3})$   # The end IP Address
                                  ''', re.VERBOSE)
        res = span_re.match(input)
        if res:
            beginning_ip = res.group(1)
            end_digit = res.group(2)
            end_ip = beginning_ip.split('.')
            end_ip[-1] = end_digit
            ending_ip = ".".join(end_ip)
            return self.range_to_ip_list(beginning_ip, ending_ip)

        cidr_re = re.compile(r'''(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})   # The IP Address
                                 /(\d{1,2})                             # The mask
                              ''', re.VERBOSE)

        res = cidr_re.match(input)
        if res:
            return self.cidr_to_iplist(input)
        return []


    def input_to_host(self, input_host):
        input_endpoint = input_host.strip()
        regex1 = r'^(http[s]?)(:\/\/)([^\/]+[^:])(:)([0-9]*)$'
        matches = re.findall(regex1, input_endpoint)
        if matches:
            host = matches[0][2]
            port = matches[0][4]
            return host, port
        regex2 = r'^(http[s]?)(:\/\/)([^\/]+)()()$'
        matches = re.findall(regex2, input_endpoint)
        if matches:
            host = matches[0][2]
            port = None
            return host, port
        regex_ip = r"(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$"
        matches = re.findall(regex_ip, input_endpoint)
        if matches:
            host = matches[0]
            port = None
            return host, port
        return None, None

    def config_file_to_host_list(self, file):
        host_list = []
        host_map = {}
        if file == 'default':
            file_full_path = f'{str(Path.home())}/.kube/config'
        else:
            file_full_path = file
        with open(file_full_path, 'r') as file:
            file_data = file.read()
        file_data = yaml.safe_load(file_data)
        for cluster_data in file_data.get('clusters'):
            host_list.append(cluster_data.get('name'))
            host_map.update({cluster_data.get('name'): cluster_data.get('cluster').get('server')})
        return host_list, host_map
