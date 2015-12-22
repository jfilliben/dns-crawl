# dns-crawl
Generate DNS entries for Cisco router interfaces using netmiko

Run with --help for input help

This script takes a list of routers and uses netmiko to log into each. It gathers the output of 'show ip interface brief'
and creates DNS entries in the requested format for inclusion in DNS.
