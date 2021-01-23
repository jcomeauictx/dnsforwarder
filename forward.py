#!/usr/bin/python -OO
'''
forward.py -- service to bypass telmex DNS blocking by forwarding to opendns

Opendns listens on port 443 in addition to 53 and 5353, in both udp and tcp
protocols. Telmex blocks all of the above except for tcp:443, which it must
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
    listener = socket.socket(socket.AF_INET, SERVER_SOCKETTYPE)
    listener.bind((SERVER, int(SERVER_PORT)))
    while True:
        query, sender = listener.recvfrom(1024)
        logging.debug('query: %r, sender: %r', query, sender)
        upstream = socket.socket(socket.AF_INET, OPENDNS_SOCKETTYPE)
        upstream.bind(('0.0.0.0', 0))
        upstream.connect((OPENDNS, int(OPENDNS_PORT)))
        length = struct.pack('>h', len(query))
        upstream.send(length + query)
        response = upstream.recv(1024)
        logging.debug('response: %r', response)
        upstream.close()
        listener.sendto(response[2:], sender)

if __name__ == '__main__':
    serve()
