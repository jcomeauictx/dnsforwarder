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
import sys, os, socket, struct, logging
OPENDNS = os.getenv('OPENDNS', '208.67.222.222')
OPENDNS_SOCKETTYPE = socket.SOCK_STREAM  # tcp
OPENDNS_PORT = '443'
SERVER = os.getenv('DNS_SERVER', '127.0.0.1')
SERVER_SOCKETTYPE = socket.SOCK_DGRAM  # udp
SERVER_PORT = '53'

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

def serve():
    '''
    forwards dns queries by pretending to be a local server
    '''
    listener = socket.socket(socket.AF_INET, SERVER_SOCKETTYPE)
    listener.bind((SERVER, int(SERVER_PORT)))
    logging.info('dnsforwarder bound to %s:%s', SERVER, SERVER_PORT)
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
    header, remainder = message[:12], message[12:]
    qdcount = int.from_bytes(header[4:6], 'big')
    ancount = int.from_bytes(header[6:8], 'big')
    nscount = int.from_bytes(header[8:10], 'big')
    arcount = int.from_bytes(header[10:12], 'big')
    records = []
    for record in range(qdcount + ancount + nscount + arcount):
        # get qname, qtype, qclass for each record
        records.append([[]])
        while ord(remainder[0:1]):
            length, remainder = ord(remainder[0:1]), remainder[1:]
            logging.debug('length: %d, remainder: %r', length, remainder)
            records[-1][0].append(remainder[:length].decode())
            remainder = remainder[length:]
        remainder = remainder[1:]  # nip zero-byte marking end of qname
        qtype, remainder = remainder[:2], remainder[2:]
        records[-1].append(int.from_bytes(qtype, 'big'))
        qclass, remainder = remainder[:2], remainder[2:]
        records[-1].append(int.from_bytes(qclass, 'big'))
    return records

if __name__ == '__main__':
    serve()
