#
# Author: Jeremy Filliben
# Created: 2015-11-10
#

# To Do:
#
# introduce threading or multi-processing
# check for newly missing interfaces, if possible (but how?)
# delete all DNS entries for routers that are down?
# Add unit tests
#

from sys import argv
import socket
from contextlib import contextmanager
import netmiko
from contextlib import contextmanager
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, NetMikoAuthenticationException
import getpass
from copy import deepcopy
import argparse

def build_router_dict(router_name, ssh_username, ssh_password, global_verbose):
#
# Builds dictionary to be passed to netmiko
#
#    detect IOS type or read it from somewhere?
#
    routerDict = {
        'device_type': 'cisco_ios',
        'ip': router_name,
        'username': ssh_username,
        'password': ssh_password,
        'verbose': global_verbose,
#        'global_delay_factor': 3,
    }
    return routerDict

@contextmanager
def ssh_manager(net_device):
    '''
    args -> network device mappings
    returns -> ssh connection ready to be used
    '''
    try:
        SSHClient = netmiko.ssh_dispatcher(
                        device_type=net_device["device_type"])
        try:
            conn = SSHClient(**net_device)
            connected = True
        except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
#            if routerDict.verbose:
#                print("could not connect to {}, due to {}".format(
#                                net_device["ip"], e))
            connected = False
    except (NetMikoTimeoutException, NetMikoAuthenticationException) as e:
#        if routerDict.verbose:
#            print("could not connect to {}, due to {}".format(
#                            net_device["ip"], e))
        connected = False
    try:
        if connected:
            yield conn
        else:
            yield False
    finally:
        if connected:
            conn.disconnect()

def get_interfaces(routerDict, global_verbose):
#
# Returns dictionary of interfaces and IP addresses
#
    returnDict = {}
    with ssh_manager(routerDict) as netConnect:
        try:
            output = netConnect.send_command('show ip interface brief',
                                             delay_factor=2)
        except Exception as e:
            if global_verbose:
                print("Encountered a non setup/teardown error", e)
            return {}
    if not output and global_verbose:
        print "output empty... too slow?"
        return {}
    if global_verbose:
        print "%s" % output
    tempOutput = output.split("\n")
    for line in tempOutput:
        tempLine = line.split()
#
# Change this if/elif structure to match on IP info? Would be simpler
#
        if not(tempLine):                         pass # empty line
        elif not(tempLine[1]):                    pass # empty line
        elif tempLine[1] == "unassigned":         pass # no IP on interface
        elif tempLine[1] == "IP-Address":         pass # IOS Header
        elif tempLine[1] == "Interface":          pass # NX-OS Header 1
        elif tempLine[1] == "IP":                 pass # NX-OS Header 2
        elif tempLine[1] == "for":                pass # exec prompt timestamp
        elif tempLine[1] == "source":             pass # exec prompt timestamp
        elif ((len(tempLine) >= 5) and
            (tempLine[4] == "administratively")): pass # admin down interface
        else:
            returnDict[tempLine[0]] = tempLine[1]
    return returnDict

def interface_identifier(intType):

    tempIntName = "".join(i for i in intType if not i in "0123456789.\/\:")
    tempIntIdentifier = "".join(i for i in intType if i in "0123456789./\:")
    tempIntIdentifier = tempIntIdentifier.replace("/", "-")
    tempIntIdentifier = tempIntIdentifier.replace(":", "-")
    tempIntIdentifier = tempIntIdentifier.replace(".", "-")
    if tempIntIdentifier == "": return "" # For unassigned interfaces
    if tempIntName == "Tunnel": return "-tu" + tempIntIdentifier
    elif tempIntName == "TenGigabitEthernet": return "-te" + tempIntIdentifier
    elif tempIntName == "Te": return "-te" + tempIntIdentifier
    elif tempIntName == "GigabitEthernet": return "-ge" + tempIntIdentifier
    elif tempIntName == "Gi": return "-ge" + tempIntIdentifier
    elif tempIntName == "FastEthernet": return "-fe" + tempIntIdentifier
    elif tempIntName == "Ethernet": return "-eth" + tempIntIdentifier
    elif tempIntName == "Vlan": return "-vlan" + tempIntIdentifier
    elif tempIntName == "BVI": return "-bvi" + tempIntIdentifier
        # BVI = Bridged Virtual Interface
    elif tempIntName == "Loopback": return "-lo" + tempIntIdentifier
    elif tempIntName == "Port-Channel": return "-po" + tempIntIdentifier
    elif tempIntName == "Port-channel": return "-po" + tempIntIdentifier
    elif tempIntName == "BDI": return "-bdi" + tempIntIdentifier
        # BDI = Bridge Domain Interface
    elif tempIntName == "ucse": return "-ucse" + tempIntIdentifier
    elif tempIntName == "Serial": return "-se" + tempIntIdentifier
    elif tempIntName == "In": return "-ise" + tempIntIdentifier
        # In = Integrated-Services-Engine
    elif tempIntName == "Multilink": return "-mu" + tempIntIdentifier
    elif tempIntName == "Dialer": return "-dialer" + tempIntIdentifier
# NX-OS output is slightly different; more compact
    elif tempIntName == "Eth": return "-eth" + tempIntIdentifier
    elif tempIntName == "Lo": return "-lo" + tempIntIdentifier
# For unlisted/unwanted interfaces, return ""
    if global_verbose: print "UNKNOWN INT TYPE ==" + intType
    return ""

def filter_dns(interfacesDict, filter_list, global_verbose):
# Remove unwanted DNS entries
    tempInterfacesDict = deepcopy(interfacesDict)
    for router in interfacesDict:
        for interface in interfacesDict[router]:
            for y in filter_list:
                if interfacesDict[router][interface][:len(y)] == y:
                    if global_verbose:
                        print "Filtering %s from %s" % (tempInterfacesDict[router][interface], router + "-" + interface)
                    del tempInterfacesDict[router][interface]
                    break
    return tempInterfacesDict

def output_bind(dnsDict, domain_name):
#
# Print 'traditional' DNS entries for BIND
#
# Generate A records
    fmt = '{0:50} {1:7} {2:}'
    for x in dnsDict:
        print fmt.format(x + domain_name, "A", dnsDict[x])
        pass
# Generate in.arpa records
    for x in dnsDict:
        tempAddr = dnsDict[x].split('.')
        reverseAddr = ''
        for y in range(0, len(tempAddr)):
            reverseAddr += tempAddr[len(tempAddr) - 1 - y] + '.'
        print fmt.format(str(reverseAddr[:-1]) + ".in-addr.arpa","PTR", \
                         x + domain_name)

def output_infoblox(dnsDict, domain_name):
#
# Infoblox CSV format
#
# Generate A records
    print "header-arecord,address*,fqdn*,comment"
    for x in dnsDict:
        print "arecord,%s,%s,add by dns_crawl" % (dnsDict[x], x + domain_name)

# Generate in.arpa records
    print "header-ptrrecord,dname*,fqdn,comment"
    for x in dnsDict:
        tempAddr = dnsDict[x].split('.')
        reverseAddr = ''
        for y in range(0, len(tempAddr)):
            reverseAddr += tempAddr[len(tempAddr) - 1 - y] + '.'
        print "ptrrecord,%s,%s.in-addr.arpa,add by dns_crawl" % \
            (x + domain_name, reverseAddr[:-1])

def create_filter_list(filter_list_lines):
# returns pattern match for DNS exclusions
# supports:
#   classful subnet mask notation (192.168.0.0/16, 10.0.0.0/8)
#   wildcard matching (192.168.*.*)
#   pattern matching (192.168., 10.)
#
    filter_list = []
    for x in filter_list_lines:
        if x and x[0] != "#":
            if "*" in x:
                filter_list.append(x[:x.index('*')])
            elif "/" in x:
                split_lines = x.split('/')
                subnet_mask = int(split_lines[1])
                octets = split_lines[0].split('.')
                if subnet_mask == 0:
                    quit("All prefixes are excluded due to subnet mask '/0' in filter list")
                elif subnet_mask <= 8:
                    if (int(octets[0]) % 2 ** (8 - subnet_mask)) != 0:
                        quit("invalid subnet mask /" + str(subnet_mask) + " for prefix " + split_lines[0])
                    for y in range(int(octets[0]), int(octets[0]) + (2 ** (8 - subnet_mask))):
                        filter_list.append(str(y) + ".")
                elif subnet_mask <= 16:
                    subnet_mask -= 8
                    if (int(octets[1]) % 2 ** (8 - subnet_mask)) != 0:
                        quit("invalid subnet mask /" + str(subnet_mask + 8) + " for prefix " + split_lines[0])
                    for y in range(int(octets[1]), int(octets[1]) + (2 ** (8 - subnet_mask))):
                        filter_list.append(octets[0] + "." + str(y) + ".")
                elif subnet_mask <= 24:
                    subnet_mask -= 16
                    if (int(octets[2]) % 2 ** (8 - subnet_mask)) != 0:
                        quit("invalid subnet mask /" + str(subnet_mask + 16) + " for prefix " + split_lines[0])
                    for y in range(int(octets[2]), int(octets[2]) + (2 ** (8 - subnet_mask))):
                        filter_list.append(octets[0] + "." + octets[1] + "." + str(y) + ".")
                elif subnet_mask <= 32:
                    subnet_mask -= 24
                    if (int(octets[3]) % 2 ** (8 - subnet_mask)) != 0:
                        quit("invalid subnet mask /" + str(subnet_mask + 24) + " for prefix " + split_lines[0])
                    for y in range(int(octets[3]), int(octets[3]) + (2 ** (8 - subnet_mask))):
                        filter_list.append(octets[0] + "." + octets[1] + "." + octets[2] + "." + str(y))
                else:
                        quit("invalid subnet mask /" + str(subnet_mask) + " for prefix " + split_lines[0])
            else:
                filter_list.append(x)
    return filter_list

def parse_args():
    parser = argparse.ArgumentParser(
                                    description = 'verifies prefix-lists for 3rd parties')
    parser.add_argument('--verbose', action='store_true',
                       help='provide additional output for verification')
    parser.add_argument('--username', help='username for SSH connections')
    parser.add_argument('--password', help='password for SSH username')
    parser.add_argument('--filename', help='source file for list of routers',
                        required = True)
    parser.add_argument('--output', choices=["infoblox", "bind"],
                        help='Output format', required = True)
    parser.add_argument('--checkdns', action='store_true',
                        help='check table against DNS and only store new/changed entries')
    parser.add_argument('--domainname',
                        help='domain name to use for DNS suffix. Will discover based on host FQDN if not supplied')
    parser.add_argument('--filterlist', help='specify filename of IP filter-list. DNS entries for IPs in the filterlist file will be suppressed. Default filter-list is "filterlist.txt"')

    args = parser.parse_args()
    if args.verbose:
        global_verbose = True
    else:
        global_verbose = False

    if args.username:
        ssh_username = args.username
    else:
        ssh_username = raw_input("Enter Username> ")
    if args.password:
        ssh_password = args.password
    else:
        ssh_password = getpass.getpass("Enter Password> ")

    if args.checkdns:
        check_dns = True
    else:
        check_dns = False

    if args.domainname:
        domain_name = args.domainname
        if domain_name[0] != '.':
            domain_name = "." + domain_name
    else:
        try:
            fqdn = socket.getfqdn()
        except Exception as e:
            print("could not determine domain name", e)
            quit()
        domain_name = fqdn[fqdn.index('.'):]

    if args.filterlist:
        filter_file = args.filterlist
    else:
        filter_file = "filterlist.txt"

    try:
        with open(filter_file) as f:
            filter_list_lines = f.read().splitlines()
    except:
        filter_list_lines = []

    filter_list = create_filter_list(filter_list_lines)

    return global_verbose, ssh_username, ssh_password, args.filename, args.output, check_dns, domain_name, filter_list

def get_router_list(filename, ssh_username, ssh_password, global_verbose):
# Takes filename and parses list of routers, then retrieves 'show ip int brief'
    with open(filename) as f:
        routerList = f.read().splitlines()

    # Initialize master list
    interfacesDict = {}

    # Loop through list of routers and build interfacesDict
    for router in routerList:
        if router:
            if (router[0] <> "#"):
                routerDict = build_router_dict(router, ssh_username, ssh_password, global_verbose)
                if routerDict:    # Test if routerDict is empty
                    interfacesDict[router] = get_interfaces(routerDict, global_verbose)
    return interfacesDict

def remove_duplicates(interfacesDict):
    #
    # Look for duplicates per router and decide which is most important
    # Tunnels are less important than physicals
    # Higher numbered tunnels are more important than lower numbered ones
    #   Lower numbers are auto-generated for PIM, WCCP, etc
    #
    tempInterfaceDict = {}
    for router in interfacesDict:
        tempRouterDict = {}
        reverseRouterDict = {}
        for interface, ip_address in interfacesDict[router].items():
            # if not in list, add it
            if not(ip_address in reverseRouterDict):
                reverseRouterDict[ip_address] = interface
            # if both are tunnels, choose the higher-numbered one
            elif interface[6:] == reverseRouterDict[ip_address][6:] \
                    == "Tunnel":
                if int(reverseRouterDict[ip_address][6:]) > int(interface[:6]):
                    reverseRouterDict[ip_address] = interface
            # if old int is a tunnel, replace it with new one
            elif reverseRouterDict[ip_address][6:] == "Tunnel":
                reverseRouterDict[ip_address][interface] = interface
        for hostname in reverseRouterDict:
            tempRouterDict[reverseRouterDict[hostname]] = hostname
        tempInterfaceDict[router] = tempRouterDict
    return tempInterfaceDict

def device_dns(interfaces):
    #
    # Select the basic DNS entry 'router.xxx.net'
    # Loopback129, then highest loopback, then highest Ethernet?
    #
    # Returns IP address in string format
    current_ip = ""
    for interface, ip_address in interfaces.items():
        if not current_ip:
            current_ip = ip_address
        elif interface in ["Loopback129","Lo129'"]:
            return ip_address
        elif interface[:2] == "Lo":
            current_ip = ip_address
    return current_ip

def create_dns_dict(interfacesDict):
# Takes as input a dictionary of interfaces and IP addresses
# Outputs dictionary of hostnames + IP addresses
#   And reverse-mapping records
#
# First generate base device DNS entry "hostname.suffix.net"
    dnsDict = {}
    for router in interfacesDict:
        base_name = device_dns(interfacesDict[router])
        if base_name:
            dnsDict[router] = base_name

# Remove duplicate entries from interfacesDict
    interfacesDict = remove_duplicates(interfacesDict)

    # Generate interface DNS dictionary
    for router in interfacesDict:
        for interface_string in interfacesDict[router]:
            dns_name = ""
            interface_name = interface_identifier(interface_string)
            if interface_name:
                dns_name = router + interface_name
                dnsDict[dns_name] = interfacesDict[router][interface_string]

    return dnsDict

def check_dns_for_entries(dnsDict, global_verbose):
# Checks DNS and removes any entries from dnsDict that are already in DNS
    if global_verbose:
        print "Checking for existing DNS entries"
    for hostname, host_ip in dnsDict.items():
        try:
            dns_ip = socket.gethostbyname(hostname)
        except:
            dns_ip = ""
        if dns_ip == host_ip:
            del dnsDict[hostname]
            if global_verbose:
                print "Removing entry '%s, %s' from list" % (hostname, host_ip)
        else:
            if global_verbose:
                print "Keeping entry '%s, %s' in list" % (hostname, host_ip)
                if dns_ip:
                    print "  Previous IP address was %s" % (dns_ip)
                else:
                    print "  No previous IP address"
    return dnsDict
#
# MAIN
#
# Handle arguments
def main():
# Get arguments / global variables
    global_verbose, ssh_username, ssh_password, filename, output, check_dns, domain_name, filter_list = parse_args()
# Get list of router interfaces
    interfacesDict = get_router_list(filename, ssh_username, ssh_password, global_verbose)
# Filter DNS based on requested filter list
    interfacesDict = filter_dns(interfacesDict, filter_list, global_verbose)
# Convert interfacesDict into DNS dictionary
    dnsDict = create_dns_dict(interfacesDict)
# If asked, run 'Check DNS' to remove entries that are already in DNS table
    if check_dns:
        dnsDict = check_dns_for_entries(dnsDict, global_verbose)
    #
    # Generate the proper DNS table based on the requested output type
    if output == "bind":
        output_bind(dnsDict, domain_name)
    elif output == "infoblox":
        output_infoblox(dnsDict, domain_name)

# __main__
if __name__ == '__main__':
    main()
