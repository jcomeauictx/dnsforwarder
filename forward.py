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
import sys, os, socket, struct, logging  # pylint: disable=multiple-imports
try:
    int.from_bytes  # pylint: disable=pointless-statement
    def netint(packed, order='big'):
        '''
        unpack unsigned network short or long with python3

        python3.9 did not have a default `order` parameter,
        and it was named `byteorder`
        '''
        return int.from_bytes(packed, order)
except AttributeError:
    def netint(packed, order='big'):
        '''
        unpack unsigned network short or long with python2
        '''
        formats = {2: '>H', 4: '>L'}
        if len(packed) not in  [2, 4] or order != 'big':
            raise NotImplementedError('netint() limited to network ints')
        return struct.unpack(formats[len(packed)], packed)[0]

OPENDNS = os.getenv('OPENDNS', '208.67.222.222')
OPENDNS_SOCKETTYPE = socket.SOCK_STREAM  # tcp
OPENDNS_PORT = '443'
SERVER = os.getenv('DNS_SERVER', '127.0.0.1')
SERVER_SOCKETTYPE = socket.SOCK_DGRAM  # udp
SERVER_PORT = '53'

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

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

def unpack(message):
    # pylint: disable=line-too-long
    r'''
    break dns query or response into its component parts
    >>> unpack(b'\xecy\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01')
    [['apple.com', 28, 1]]
    >>> unpack(b'\x007\xecy\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x03\x07\x00\x10& \x01I\n\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'[2:])
    [['apple.com', 28, 1], ['apple.com', 28, 1, 775, 16, b'& \x01I\n\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10']]
    '''
    qdcount = netint(message[4:6])
    ancount = netint(message[6:8])
    nscount = netint(message[8:10])
    arcount = netint(message[10:12])
    logging.debug({'qdcount': qdcount, 'ancount': ancount,
                   'nscount': nscount, 'arcount': arcount})
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
            records.append([name, qtype, qclass, ttl, rdlength, rdata])
            offset += 6 + rdlength
        logging.debug('unprocessed remainder: %r', message[offset:])
    return records

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
    # pylint: disable=consider-using-f-string
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

if __name__ == '__main__':
    serve()
