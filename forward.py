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
    short = int.from_bytes
except AttributeError:
    def short(packed, order='big'):
        '''
        unpack unsigned network short on python2
        '''
        if len(packed) != 2 or order != 'big':
            raise NotImplementedError('short() limited to network shorts')
        return struct.unpack('>H', packed)[0]
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
                'Port %s already in use; is avahi-daemon running?' % port
            )
            sys.exit(1)
    logging.info('dnsforwarder bound to %s:%s', SERVER, port)
    while True:
        query, sender = listener.recvfrom(1024)
        logging.debug('query: %r, sender: %r', unpack(query), sender)
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
    '''
    break dns query or response into its component parts
    '''
    qdcount = short(message[4:6], 'big')
    ancount = short(message[6:8], 'big')
    nscount = short(message[8:10], 'big')
    arcount = short(message[10:12], 'big')
    logging.debug({'qdcount': qdcount, 'ancount': ancount,
                   'nscount': nscount, 'arcount': arcount})
    records = []
    offset = 12
    for record in range(qdcount + ancount + nscount + arcount):
        logging.debug('processing record %d, message %r, length %d',
                      record, message, len(message))
        # get qname, qtype, qclass for each record
        offset, name = unpack_name(message, offset)
        qtype = short(message[offset:offset + 2])
        qclass = short(message[offset + 2:offset + 4])
        offset += 4
        logging.debug('unprocessed remainder: %r', message[offset:])
        if record < qdcount:
            records.append([name, qtype, qclass])
            continue
        else:
            break  # FIXME: add remaining fields here
    return records

def unpack_name(message, offset, parts=None):
    '''
    unpack the "name" portion of a message

    return the new offset, and the name as a dotted string
    '''
    parts = parts or []
    count = ord(message[offset:offset + 1])
    if count & 0xc0 == 0xc0:
        offset = (count & 0x3f) << 8 + ord(message[offset + 1:offset + 2])
        logging.debug('found name pointer to offset %d', offset)
        return unpack_name(message, offset, parts)
    elif 0 < count < 0x40:
        parts.append(message[offset + 1:offset + 1 + count].decode())
        return unpack_name(message, offset + 1 + count, parts)
    elif count == 0:
        return (offset + 1, '.'.join(parts))
    else:
        raise ValueError('count of 0x%02x not supported', count)

if __name__ == '__main__':
    serve()
