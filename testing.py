import bencode
import requests
import sha
import struct
import socket

def decode(file):
    ''' Decodes the bencoded file, returns decoded dictionary '''
    torrent = bencode.bdecode(open(file, 'rb').read())
    return torrent

def recvall(socket, expected):
    ''' Allows you to receive an expected amount off a socket '''
    data = ''
    while True:
        newdata = socket.recv(expected)
        data += newdata
        expected -= len(newdata)
        if not expected:
            break
    return data

def spliceshas(torrent):
    ''' Splices the SHA1 keys into a list '''
    tor = bencode.bdecode(open(torrent, 'rb').read()) 
    print tor['info'].keys()
    print tor['info']['piece length']
    pieces = tor['info']['pieces']
    pieceshas = []

    for i in range(len(pieces)/20):
       pieceshas.append(pieces[20*i:20*(i+1)])

    return pieceshas


''' Tracker '''

def announce(file):
    ''' Announces to a tracker 
    
    Currently returns 1 peer's IP and port, hardcoded '''
    info_hash = getdicthash(file)
    torrent = decode(file)
    payload = {'info_hash': info_hash,
               'peer_id':'-TR2610-dfhmjb0skee6',
               'port':'6881',
               'uploaded':'0',
               'downloaded':'0',
               'key':'2c4dec5f',
               'left':'50000',
               'no_peer_id':'0',
               'event':'started',
               'compact':'1',
               'numwant':'30'}

    response = requests.get(torrent['announce'], params = payload)
    reply = bencode.bdecode(response.content)
    print("""
+Response received, decoded..
+peers: {0}
+complete: {1}
+interval: {2}
+incomplete: {3}
+""".format(repr(reply['peers']), reply['complete'], reply['interval'], reply['incomplete']))
    
    data = reply['peers']
    multiple = len(data)/6
    print struct.unpack("!" + "LH"*multiple, data)
    for i in range(0, multiple):
        print socket.inet_ntop(socket.AF_INET, data[6*i:6*i+4]) + ":" + repr(struct.unpack("!H", data[6*i+4:6*i+6])[0])
    ip =  socket.inet_ntop(socket.AF_INET, data[0:4])
    port = int(repr(struct.unpack("!H", data[4:6])[0]))
    return (ip, port)



''' Peer '''

def handshake(socket):
    ''' Initiates handshake with peer '''
    info_hash = getdicthash('Sapolsky.mp4.torrent')    
    msg = chr(19) + 'BitTorrent protocol' + '\x00'*8 + info_hash + '-TR2610-dfhmjb0skee6'
    socket.send(msg)
    print "Handshake sent: ", repr(msg)
    print "Handshake rcvd: %s" % repr(socket.recv(4096))


def make_request(piece, offset, length):
    ''' Constructs msg for requesting a block from a peer

    Need to add in begin, offset, length as vars '''
    return struct.pack('!L', 13) + chr(6) + struct.pack('!LLL', piece, offset, 16384)



def flagmsg(socket):
    ''' Takes a bit off socket buffer; returns a tuple of the action and the data from a socket

    BLOCKS'''
    first  = socket.recv(4)
    length = struct.unpack('!L', first)[0]
    id_data = recvall(socket, length)
    if not id_data:
        return
    id = id_data[0]
    data = id_data[1:]
    id_dict1 = {'\x01': 'unchoke', '\x00': 'choke', '\x03': 'not interested', '\x02': 'interested'}
    id_dict2 = {'\x05': 'bitfield', '\x04': 'have', '\x07': 'piece', '\x06': 'request', '\x08': 'cancel'}
    if (id in id_dict1):
    	return (id_dict1[id], None)
    else:
		return (id_dict2[id], data)


def receive_loop(s):
    piece_data = [None]*131072
    while True:
        flag, data = flagmsg(s)
        print flag
        if flag == 'bitfield':
            num = int(data.encode('hex'), 16)
            bitfield = bin(num)[2:len(spliceshas('Sapolsky.mp4.torrent'))+2]
            bfield = [ (True if x == '1' else False) for x in bitfield ]
            print bitfield
            print bfield[0:10]
        elif flag == 'unchoke':
            ''' If unchoked, send a request! '''
            print 'unchoked!'
            s.sendall(make_request(0, 0, 16384))
            last_req_length = 16384
            # we don't actually need this, can get from length of data. attribute it?
        elif flag == 'piece':
            piece, offset = struct.unpack('!LL', data[:8])
            print repr(data[:20])
            print piece, offset
            print len(data[8:])
            piece_data[offset:offset+last_req_length] = data[8:]
            if None not in piece_data:
                print "yay!"
                break
            first_blank = piece_data.index(None)
            size_left = piece_data.count(None)
            s.sendall(make_request(0, first_blank, min(16384, size_left)))
            last_req_length = min(16384, size_left)
    return piece_data


def getdicthash(file):
    ''' Returns the SHA1 hash of the 'info' key in the metainfo file '''
    contents = open(file, 'rb').read()
    start = contents.index('4:info') + 6
    end = -1
    dictliteral = contents[start:end]
    dictsha = sha.new(dictliteral)
    return dictsha.digest()






def main():
    pieceshas = spliceshas('Sapolsky.mp4.torrent')
    ip, port = announce('Sapolsky.mp4.torrent')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    s.connect((ip, 51413))
    handshake(s)
    first_block = receive_loop(s)
    print pieceshas[0]
    first_block = "".join(first_block)
    first_block = sha.new(first_block).digest()
    print first_block

if __name__ == '__main__':
    main()



'''
class Peer(Protocol):
    def __init__(self, address):
        self.write(handshake?)
    def dataReceived(self, data):
        self.data += data
        # bunch of if statements

class PeerFactory():
    def buildProtocol(address):
        Peer(address)

if __name__ == '__main__':
    fac = PeerFactory()
    for peer in peerList
        fac.buildProtocol(peer)

'''
