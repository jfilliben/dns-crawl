import unittest
from dns_crawl import filter_dns

interfacesDict = {'test_router': {u'GigabitEthernet0/0/0': u'5.5.5.5', u'GigabitEthernet0/0/1': u'10.44.16.34', u'GigabitEthernet0/0/2': u'192.0.2.1', u'GigabitEthernet0/0/3': u'10.32.1.3', u'Loopback129': u'10.1.32.2', u'Tunnel10': u'192.168.136.40', u'Tunnel11': u'192.168.140.40', u'Loopback100': u'5.5.6.1', u'Tunnel0': u'10.44.16.162'}}
filter_list = ['192.168.', '192.0.2.']

print dns_crawl.filter_dns(interfacesDict, filter_list, False)
