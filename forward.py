#!/usr/bin/python3 -OO
'''
forward.py -- service to bypass telcel DNS blocking by forwarding to opendns

Opendns listens on port 443 in addition to 53 and 5353, in both udp and tcp
protocols. Telcel blocks all of the above except for tcp:443, which it must
pass for web traffic.

DNS queries over TCP have two additional bytes prepended, the length of the
packet not counting the two bytes of the length field itself. I did not find
this documented anywhere, but observed it in `ngrep -x` output.
'''
import sys, os, socket, struct, re, logging  # pylint: disable=multiple-imports
from collections import OrderedDict
# flags
RESPONSE = 0x8000
OPCODE_MASK = 0x7800
AUTHORITATIVE = 0x400
TRUNCATION = 0x200
RECURSION_DESIRED = 0x100
RECURSION_AVAILABLE = 0x80
RESERVED_MASK = 0x70
RETURN_CODE_MASK = 0xf
# pylint: disable=bad-option-value,consider-using-f-string
try:
    int.from_bytes  # pylint: disable=pointless-statement
    def netint(packed, order='big'):
        '''
        unpack unsigned network short or long with python3

        python3.9 did not have a default `order` parameter,
        and it was named `byteorder`
        '''
        return int.from_bytes(packed, order)
    def intstr(unpacked, order='big', length=2):
        '''
        pack unsigned integer into network order
        '''
        return unpacked.to_bytes(length, order)
except AttributeError:
    def netint(packed, order='big'):
        '''
        unpack unsigned network short or long with python2
        '''
        formats = {2: '>H', 4: '>L'}
        if len(packed) not in  [2, 4] or order != 'big':
            raise NotImplementedError('netint() limited to network ints')
        return struct.unpack(formats[len(packed)], packed)[0]
    def intstr(unpacked, order='big', length=2):
        '''
        pack unsigned integer into network order
        '''
        formats = {2: '>H', 4: '>L'}
        if length not in [2, 4] or order != 'big':
            raise NotImplementedError('intstr() limited to network ints')
        return struct.pack(formats[length], unpacked)
try:
    unichr  # pylint: disable=used-before-assignment
except NameError:
    unichr = chr

OPENDNS = os.getenv('OPENDNS', '208.67.222.222')
OPENDNS_SOCKETTYPE = socket.SOCK_STREAM  # tcp
OPENDNS_PORT = '443'
SERVER = os.getenv('DNS_SERVER', '127.0.0.1')
SERVER_SOCKETTYPE = socket.SOCK_DGRAM  # udp
SERVER_PORT = '53'

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

class DNSMessage():  # pylint: disable=too-few-public-methods
    # pylint: disable=line-too-long
    r'''
    represent a DNS message

    >>> DNSMessage(b'\x007\xecy\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x03\x07\x00\x10& \x01I\n\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'[2:])
    [0xec79]
    '''
    def __init__(self, data=None):
        self.tid = 0
        self.flags = 0
        self.records = [[], [], [], []]
        if data:
            if hasattr(data, 'decode'):  # bytes or equivalent
                self.raw = data
                self.tid = netint(data[0:2])
                self.flags = netint(data[2:4])
                self.records[0].extend([None] * netint(data[4:6]))
                self.records[1].extend([None] * netint(data[6:8]))
                self.records[2].extend([None] * netint(data[8:10]))
                self.records[3].extend([None] * netint(data[10:12]))
            else:  # list
                self.tid = data[0]
                self.flags = data[1]
                self.records = data[2]
                self.raw = b''

    def __str__(self):
        return '[' + '0x%x' % self.tid + ']'

    __repr__ = __str__

    qdcount = property(lambda self: len(self.records[0]))
    ancount = property(lambda self: len(self.records[1]))
    nscount = property(lambda self: len(self.records[2]))
    arcount = property(lambda self: len(self.records[3]))

def serve(port=SERVER_PORT):
    '''
    forwards dns queries by pretending to be a local server
    '''
    listener = socket.socket(socket.AF_INET, SERVER_SOCKETTYPE)
    try:
        listener.bind((SERVER, int(port)))
    except PermissionError:
        port *= 2  # try with port 5353
        try:
            listener.bind((SERVER, int(port)))
        except OSError:
            logging.error(
                'Port %s already in use; is avahi-daemon running?', port
            )
            sys.exit(1)
    logging.info('dnsforwarder bound to %s:%s', SERVER, port)
    while True:
        query, sender = listener.recvfrom(1024)
        logging.debug(
            'query: %r (%s), sender: %r',
            query, unpack(query), sender
        )
        upstream = socket.socket(socket.AF_INET, OPENDNS_SOCKETTYPE)
        upstream.bind(('0.0.0.0', 0))
        upstream.connect((OPENDNS, int(OPENDNS_PORT)))
        length = struct.pack('>h', len(query))
        upstream.send(length + query)
        response = upstream.recv(1024)
        logging.debug('response: %r', response)
        upstream.close()
        listener.sendto(response[2:], sender)

def unpack(message):  # pylint: disable=too-many-locals
    # pylint: disable=line-too-long
    r'''
    break dns query or response into its component parts

    >>> unpack(b'\xecy\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01')
    OrderedDict({'tid': 60537, 'flags': 256, 'qdcount': 1, 'ancount': 0, 'nscount': 0, 'arcount': 0, 'records': [['apple.com', 28, 1]]})
    >>> unpack(b'\x007\xecy\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x03\x07\x00\x10& \x01I\n\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'[2:])
    OrderedDict({'tid': 60537, 'flags': 33152, 'qdcount': 1, 'ancount': 1, 'nscount': 0, 'arcount': 0, 'records': [['apple.com', 28, 1], ['apple.com', 28, 1, 775, 16, '2620:149:af0::10']]})
    '''
    tid = netint(message[0:2])
    flags = netint(message[2:4])
    qdcount = netint(message[4:6])
    ancount = netint(message[6:8])
    nscount = netint(message[8:10])
    arcount = netint(message[10:12])
    unpacked = OrderedDict([
        ['tid', tid], ['flags', flags],
        ['qdcount', qdcount], ['ancount', ancount],
        ['nscount', nscount], ['arcount', arcount]
    ])
    records = []
    offset = 12
    for record in range(qdcount + ancount + nscount + arcount):
        logging.debug('processing record %d, message %r, length %d',
                      record, message[offset:], len(message[offset:]))
        # get qname, qtype, qclass for each record
        offset, name = unpack_name(message, offset)
        qtype = netint(message[offset:offset + 2])
        qclass = netint(message[offset + 2:offset + 4])
        offset += 4
        if record < qdcount:
            records.append([name, qtype, qclass])
        else:
            ttl = netint(message[offset:offset + 4])
            rdlength = netint(message[offset + 4:offset + 6])
            rdata = message[offset + 6:offset + 6 + rdlength]
            if (qtype, qclass, len(rdata)) == (1, 1, 4):
                rdata = unpack_ipv4(rdata)
            elif (qtype, qclass, len(rdata)) == (28, 1, 16):
                rdata = unpack_ipv6(rdata)
            records.append([name, qtype, qclass, ttl, rdlength, rdata])
            offset += 6 + rdlength
        logging.debug('unprocessed remainder: %r', message[offset:])
    unpacked['records'] = records
    return unpacked

def pack(message):  # pylint: disable=too-many-locals
    r'''
    opposite of `unpack`: packs message into DNS packet

    >>> pack({'tid': 0xec79, 'flags': RECURSION_DESIRED, 'records': [['apple.com', 28, 1]]})
    b'\xecy\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01'
    '''
    # not supporting nameserver or associated records for now
    flags = qdcount = ancount = nscount = arcount = 0
    packed = b''
    packaddr = {1: pack_ipv4, 28: pack_ipv6}
    for packet in message['records']:
        if len(packet) not in (3, 6):
            raise ValueError('message of length %s unsupported' % len(message))
        name, qtype, qclass = packet
        packed += pack_name(name) + intstr(qtype) + intstr(qclass)
        if len(packet) == 6:  # answer
            ttl, rdlength, rdata = packet[3:]
            packed += intstr(ttl, length=4) + intstr(rdlength)
            packed += packaddr.get(qtype, lambda o: o)(rdata)
            ancount += 1
        else:
            qdcount += 1
    flags |= message.get('flags', 0)
    header = intstr(message['tid']) + intstr(flags)
    header += b''.join(
        intstr(count) for count in [qdcount, ancount, nscount, arcount]
    )
    return header + packed

def unpack_name(message, offset, parts=None):
    '''
    unpack the "name" portion of a message

    return the new offset, and the name as a dotted string
    '''
    parts = parts or []
    count = ord(message[offset:offset + 1])
    if count & 0xc0 == 0xc0:
        reference = netint(message[offset:offset + 2]) & 0x3fff
        logging.debug('found name pointer to offset %d', reference)
        return offset + 2, unpack_name(message, reference, parts)[1]
    if 0 < count < 0x40:
        parts.append(message[offset + 1:offset + 1 + count].decode())
        return unpack_name(message, offset + 1 + count, parts)
    if count == 0:
        return (offset + 1, '.'.join(parts))
    raise ValueError('count of 0x%02x not supported' % count)

def pack_name(dotname):
    r'''
    convert dotted name into DNS name format, including trailing null

    >>> pack_name('apple.com')
    b'\x05apple\x03com\x00'
    '''
    parts = dotname.split('.')
    name = b''
    for part in parts:
        name += (chr(len(part)) + part).encode()
    return name + b'\0'

def pack_ipv4(address):
    r'''
    pack dot-notation IPv4 address into netint

    >>> pack_ipv4('127.0.0.1')
    b'\x7f\x00\x00\x01'
    '''
    return struct.pack('BBBB', *map(int, address.split('.')))

def unpack_ipv4(address):
    r'''
    unpack netint IPv4 address to dot notation

    >>> unpack_ipv4(b'\x7f\x00\x00\x01')
    '127.0.0.1'
    '''
    return '.'.join(map(str, struct.unpack('BBBB', address)))

def pack_ipv6(address):
    # pylint: disable=line-too-long
    r'''
    pack colon-notation IPv6 address into netint

    >>> pack_ipv6('::1')
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'

    >>> pack_ipv6('fe80::be03:58ff:fe53:a84a')
    b'\xfe\x80\x00\x00\x00\x00\x00\x00\xbe\x03X\xff\xfeS\xa8J'

    >>> pack_ipv6('fe80::')
    b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    '''
    parts = address.split(':')
    while '' in parts:
        length = len(list(filter(None, parts)))
        index = parts.index('')
        parts[index:index + 1] = ['0'] * (8 - length)
    return struct.pack('>8H', *map(lambda n: int(n, 16), parts))

def unpack_ipv6(address):
    # pylint: disable=line-too-long
    r'''
    convert raw 128-bit address into colon notation

    >>> unpack_ipv6(b'\xfe\x80\x00\x00\x00\x00\x00\x00\xbe\x03X\xff\xfeS\xa8J')
    'fe80::be03:58ff:fe53:a84a'
    >>> [unpack_ipv6(pack_ipv6(a)) for a in ['::1', 'fe80::']]
    ['::1', 'fe80::']
    '''
    unpacked = struct.unpack('>8H', address)
    unistr = ''.join(map(unichr, unpacked))
    runs = re.findall('\x00+', unistr)
    index = None  # index to longest run of zeroes
    stringified = ['%x' % n for n in unpacked]
    if runs:
        longest = max(runs, key=len)
        index = unistr.index(longest)  # returns leftmost if a tie (good)
        # this will produce 3 colons if somewhere in the middle
        stringified[index:index + len(longest)] = ['', '']
    return ':'.join(stringified).replace(':::', '::')

if __name__ == '__main__':
    serve()
