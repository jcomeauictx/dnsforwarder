#!/usr/bin/python3 -OO
'''
forward.py -- service to bypass telcel DNS blocking by forwarding to opendns

Also imports hosts file and short-circuits any requests for hosts therein.
Totally unnecessary on standard GNU/Linux but useful with iSH app for iphone,
because /etc/hosts on iSH Alpine is hidden from iOS and thus browsers.

Opendns listens on port 443 in addition to 53 and 5353, in both udp and tcp
protocols. Telcel blocks all of the above except for tcp:443, which it must
pass for web traffic.

DNS queries over TCP have two additional bytes prepended, the length of the
packet not counting the two bytes of the length field itself. I did not find
this documented anywhere, but observed it in `ngrep -x` output.
'''
import sys, os, socket, struct, re, logging  # pylint: disable=multiple-imports
from hostsfile import hostsfile

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)
logging.quiet = lambda *args, **kwargs: logging.log(
    logging.NOTSET, *args, **kwargs
)

# flag field constants
RESPONSE = 0x8000
OPCODE_MASK = 0x7800
AUTHORITATIVE = 0x400
TRUNCATION = 0x200
RECURSION_DESIRED = 0x100
RECURSION_AVAILABLE = 0x80
RESERVED_MASK = 0x70
RETURN_CODE_MASK = 0xf

OPENDNS = os.getenv('OPENDNS', '208.67.222.222')
OPENDNS_SOCKETTYPE = socket.SOCK_STREAM  # tcp
OPENDNS_PORT = '443'
SERVER = os.getenv('DNS_SERVER', '127.0.0.1')
SERVER_SOCKETTYPE = socket.SOCK_DGRAM  # udp
SERVER_PORT = '53'

INTERNET_CLASS = 1  # for qclass
# pylint: disable=bad-option-value, consider-using-f-string
# pylint: disable=consider-using-enumerate
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

class DNSRecord():  # pylint: disable=too-many-instance-attributes
    # pylint: disable=line-too-long
    r'''
    represent a DNS record

    >>> DNSRecord(b'\x007\xecy\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x03\x07\x00\x10& \x01I\n\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'[2:], offset=12, query=True)
    ['apple.com', 0x1c, 0x1]
    '''
    def __init__(self, data=None, message=None, offset=None, query=False):
        self.message = message  # associated message if given
        self._raw = None
        self.qname = None
        self.qtype = None
        self.qclass = None
        self.ttl = None
        self.rdata = None
        self.offset = offset  # offset into message
        if message and not data:
            data = message._raw
        if isinstance(data, bytes):
            if offset is None:
                logging.debug('DNSRecord assuming offset of 12')
                self.offset = offset = 12
            offset, self.qname = unpack_name(data, offset)
            self.qtype = netint(data[offset:offset + 2])
            self.qclass = netint(data[offset + 2:offset + 4])
            offset += 4
            if not query:
                self.ttl = netint(data[offset:offset + 4])
                rdlength = netint(data[offset + 4:offset + 6])
                self.rdata = data[offset + 6:offset + 6 + rdlength]
                offset += 6 + rdlength
                if (self.qtype, self.qclass, len(self.rdata)) == (1, 1, 4):
                    self.rdata = unpack_ipv4(self.rdata)
                elif (self.qtype, self.qclass, len(self.rdata)) == (28, 1, 16):
                    self.rdata = unpack_ipv6(self.rdata)
            self._raw = data[self.offset:offset]
        elif data:
            self.qname = data[0]
            self.qtype = data[1]
            self.qclass = data[2]
            if len(data) > 3:  # don't require `query` parameter if cooked
                self.ttl = data[3]
                self.rdata = data[4]
        else:
            logging.error('DNSRecord useless without data')

    def __str__(self):
        string = (
            '[' +
              '%r' % self.qname + ', ' +
              '0x%x' % self.qtype + ', ' +
              '0x%x' % self.qclass
        )
        if self.ttl is not None:
            string += str(self.ttl) + ', '
            string += '%r' % self.rdata
        string += ']'
        return string

    __repr__ = __str__

    def __getitem__(self, key):
        mapping = {0: self.qname, 1: self.qtype, 2: self.qclass}
        return mapping[key]

    def getraw(self):
        '''
        create "raw" bytes for this record

        has side effect of setting self._raw
        '''
        logging.debug('making raw representation of %s', self)
        self._raw = (
            pack_name(self.qname) +
            intstr(self.qtype) +
            intstr(self.qclass)
        )
        if self.ttl is not None:
            self._raw += intstr(self.ttl, length=4)
            # assuming rdata also is not None
            if isinstance(self.rdata, bytes):
                rdata = self.rdata
            else:
                if ':' in rdata:
                    rdata = pack_ipv6(rdata)
                else:
                    rdata = pack_ipv4(rdata)
            self.raw = intstr(len(rdata)) + rdata
        return self._raw

    raw = property(lambda self: self._raw or self.getraw())

class DNSMessage():  # pylint: disable=too-few-public-methods
    # pylint: disable=line-too-long
    r'''
    represent a DNS message

    >>> DNSMessage(b'\x007\xecy\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x05apple\x03com\x00\x00\x1c\x00\x01\xc0\x0c\x00\x1c\x00\x01\x00\x00\x03\x07\x00\x10& \x01I\n\xf0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'[2:])
    [0xec79, 0x8180, [[['apple.com', 0x1c, 0x1]], [['apple.com', 0x1c, 0x1775, '2620:149:af0::10']], [], []]]
    '''
    def __init__(self, data=None):
        self.tid = 0
        self.flags = 0
        self.records = [[], [], [], []]
        if data:
            if isinstance(data, bytes):  # works on both py2 and 3
                self._raw = data
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
                self._raw = (
                    intstr(self.tid) +
                    intstr(self.flags) +
                    intstr(len(self.records[0])) +
                    intstr(len(self.records[1])) +
                    intstr(len(self.records[2])) +
                    intstr(len(self.records[3]))
                )
        offset = 12  # point past header to records
        # if any records were initialized as None, they should all be;
        # otherwise, this step can produce wrong results
        for i in range(len(self.records)):
            for j in range(len(self.records[i])):
                if not hasattr(self.records[i][j], 'qname'):
                    if self.records[i][j] is None:
                        self.records[i][j] = DNSRecord(
                            self._raw, offset=offset, query=(i == 0)
                        )
                        offset += len(self.records[i][j].raw)
                        logging.debug('raw record: %r, new offset: %d',
                                      self.records[i][j].raw, offset)
                    else:
                        self.records[i][j] = DNSRecord(self.records[i][j])
                        self._raw += self.records[i][j].raw

    def __str__(self):
        return ('[' +
                '0x%x' % self.tid + ', ' +
                '0x%04x' % self.flags + ', ' +
                str(self.records) +
                ']'
               )

    __repr__ = __str__

    def __add__(self, other):
        if other is None:
            return self
        raise NotImplementedError('DNSMessage.add not yet implemented')

    qdcount = property(lambda self: len(self.records[0]))
    ancount = property(lambda self: len(self.records[1]))
    nscount = property(lambda self: len(self.records[2]))
    arcount = property(lambda self: len(self.records[3]))

    # unlike record.raw, we should regenerate at each access,
    # because we don't know if records have been added/removed
    def getraw(self):
        '''
        create a "raw" bytes representation of this message
        '''
        if self.records[1] + self.records[2] + self.records[3]:
            if not self.flags & RESPONSE:
                self.flags |= RESPONSE | AUTHORITATIVE
        _raw = (intstr(self.tid) +
                intstr(self.flags) +
                intstr(self.qdcount) +
                intstr(self.ancount) +
                intstr(self.nscount) +
                intstr(self.arcount)
        )
        for i in range(len(self.records)):
            for j in range(len(self.records[i])):
                _raw += self.records[i][j].raw
        return _raw

    raw = property(lambda self: self.getraw())

def serve(port=SERVER_PORT):
    '''
    forwards dns queries by pretending to be a local server
    '''
    listener = socket.socket(socket.AF_INET, SERVER_SOCKETTYPE)
    try:
        hosts = hostsfile()
        # map host entries to qtype
        hosts[1] = hosts['ipv4']  # for A queries
        hosts[28] = hosts['ipv6']  # for AAAA queries
    except OSError:
        hosts = {1: {}, 28: {}}
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
        message = DNSMessage(query)
        # initialize a response based on the same query
        response = DNSMessage(query)
        logging.debug(
            'query: %r (%s), sender: %r', query, message, sender
        )
        for i in range(len(message.records[0])):
            record = message.records[0][i]
            if record.qname in hosts[record.qtype]:
                logging.debug('short-circuiting query for %s', record.qname)
                response.records[1].append(
                    DNSRecord(
                        [hosts[record.qtype][record.qname],
                         record.qtype, INTERNET_CLASS]
                    )
                )
                # now remove this record from query
                message.records[0].pop(i)
        if response.ancount:
            logging.debug('we short-circuited at least one query')
            if message.qdcount:
                logging.debug('we still have queries to send upstream')
                query = message.raw
            else:
                logging.debug('we have no more queries to send upstream')
                query = None
        else:
            logging.debug('message to upstream was not modified')
            response = None
        if query:
            upstream = socket.socket(socket.AF_INET, OPENDNS_SOCKETTYPE)
            upstream.bind(('0.0.0.0', 0))
            upstream.connect((OPENDNS, int(OPENDNS_PORT)))
            # TCP queries have a short length prepended
            length = struct.pack('>H', len(query))
            upstream.send(length + query)
            received = upstream.recv(1024)[2:]
            logging.debug('received: %r', received)
            response = DNSMessage(received) + response
            upstream.close()
        logging.debug('response: %s, raw: %r', response, response.raw)
        listener.sendto(response.raw, sender)

def unpack_name(message, offset, parts=None):
    '''
    unpack the "name" portion of a message

    return the new offset, and the name as a dotted string
    '''
    logging.quiet('unpacking name from %r', message[offset:offset + 64])
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
