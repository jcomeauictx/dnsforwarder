#!/usr/bin/python3 -OO
'''
read in hosts file as dict

maps names with IP addresses to override DNS queries and add
custom TLD resolution.
'''
from __future__ import unicode_literals, with_statement
import sys, io, logging  # pylint: disable=multiple-imports
try:
    # pylint: disable=used-before-assignment, invalid-name
    unicode
except NameError:
    unicode = str
logging.basicConfig(level=logging.DEBUG if __debug__ else logging.INFO)

def hostsfile():
    '''
    read in /etc/hosts and return a dict
    '''
    # according to hosts manpage, it is allowed to have two entries
    # for each hostname, one for each version of the IP protocol (v4 and v6)
    hosts = {'ipv4': {}, 'ipv6': {}}
    with io.open('/etc/hosts', encoding='utf-8') as infile:
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
                protocol = 'ipv6' if ':' in parts[0] else 'ipv4'
                for hostname in parts[1:]:
                    if hostname in hosts[protocol]:
                        logging.warning(
                            'overriding entry %s %s with %s',
                            hostname, hosts[protocol][hostname], parts[0]
                        )
                    hosts[protocol][hostname] = parts[0]
    return hosts

if __name__ == '__main__':
    print(hostsfile(*sys.argv[1:]))
