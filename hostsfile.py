#!/usr/bin/python -OO
'''
read in hosts file as dict

maps names with IP addresses to override DNS queries and add
custom TLD resolution.
'''
import sys, os, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

def hostsfile():
    '''
    read in /etc/hosts and return a dict
    '''
    with open('/etc/hosts') as infile:
        hosts = {}
        for line in infile:
            if '#' in line:
                data, comment = line.split('#', 1)
            else:
                data, comment = line, None
            logging.debug('data: %r, comment: %r', data, comment)
            parts = data.split()
            if len(parts) < 2:
                logging.error('skipping malformed entry %r', line)
            else:
                for hostname in parts[1:]:
                    if hostname in hosts:
                        logging.warn(
                            'overriding entry %s %s with %s',
                            hostname, hosts[hostname], parts[0]
                        )
                    hosts[hostname] = parts[0]
    return hosts

if __name__ == '__main__':
    print(hostsfile(*sys.argv[1:]))
