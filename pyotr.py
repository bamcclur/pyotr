import bencode
import requests
import sha
import struct
import socket
import Queue
import threading
import time
import random
import os
from dns.inet import inet_ntop as inet_ntop

    

''' Metainfo '''

def decode(file_load):
    ''' Decodes the bencoded file, returns decoded dictionary '''
    return bencode.bdecode(open(file_load, 'rb').read())



def splice_shas(pieces):
    ''' Splices the SHA1 keys into a list '''
    sha_list = []

    for i in range(len(pieces)/20):
        sha_list.append(pieces[20*i:20*(i+1)])
    return sha_list


def get_dict_hash(file_load):
    ''' Returns the SHA1 hash of the 'info' key in the metainfo file '''
    contents = open(file_load, 'rb').read()
    start = contents.index('4:info') + 6
    end = -1
    dict_literal = contents[start:end]
    dict_sha = sha.new(dict_literal)
    return dict_sha.digest()



''' Networking? '''





''' Tracker '''


def announce(metainfo, left, info_hash):
    ''' Announces to a tracker 
    
    Currently returns 1 peer's IP and port, hardcoded '''
    payload = {'info_hash': info_hash,
               'peer_id':'-PYOTR0-dfhmjb0skee6',
               'port':'57710',
               'uploaded':'0',
               'downloaded':'0',
               'key':'2c4dec5f',
               'left': left,
               'no_peer_id':'0',
               'event':'started',
               'compact':'1',
               'numwant':'30'}
    
    print("Announcing to tracker...")
    
    response = requests.get(metainfo['announce'], params = payload)
    try:
        reply = bencode.bdecode(response.content)
    except:
        print("Not a valid bencoded string '" + response.content + "'")
    print("""
Response received, decoded..
peers: {0}
complete: {1}
interval: {2}
incomplete: {3}
""".format(repr(reply['peers']), reply['complete'], reply['interval'], reply['incomplete']))
    data = reply['peers']
    print data
    print ""
    peer_list = []
    for i in range(0, len(data)/6):
        peer_list.append((inet_ntop(2, data[6*i:6*i+4]), 
                         struct.unpack("!H", data[6*i+4:6*i+6])[0]))
    
    '''There exists a scenario where even though we've specified compact, 
    we do not get a compact result, the following is to handle this case'''    
    if (peer_list == []):
        for i in range(0, len(data)):
            peer_list.append((data[i]['ip'], data[i]['port']))
    print peer_list
    return peer_list


''' Peer '''

class Peer(threading.Thread):
    ''' Grab blocks from peers, pulling indices off queue '''
    def __init__(self, piece_queue, ip, port, info_hash):
        threading.Thread.__init__(self)
        self.piece_queue = piece_queue
        self.write_queue = write_queue
        self.port = port
        self.ip = ip
        self.info_hash = info_hash
		
    def receive_loop(self, index):
        ''' Gets multiple blocks now '''
        if piece_queue.empty():
            print "piece_queue empty"
            print ""
            piece_data = [None]*(file_size%piecelength)
        else: 
            print "piece_queue not empty"
            print ""
            piece_data = [None]*piece_length
        while True:
            flag, data = self.flagmsg()
            print "Message type:", flag
            if flag == 'choke':
                print 'Peer choked us! :('
            elif flag == 'unchoke':
                ''' If unchoked, send a request! '''
                print 'Peer unchoked us!'
                time.sleep(1)
                print 'Requesting block'
                self.s.sendall(self.make_request(index, 0, 16384))
                # we don't actually need this, can get from length of data. attribute it?
            elif flag == 'interested':
                print "Peer wants stuff we have."
            elif flag == 'not interested':
                print "Peer is not interested in what we have so far."
            elif flag == 'have':
                print "Peer now has this piece " + str(index)
            elif flag == 'bitfield':
                num = int(data.encode('hex'), 16)
                bitfield = bin(num)[2:len(sha_list)+2]
                bfield = [ (True if x == '1' else False) for x in bitfield ]
                print bitfield
                time.sleep(1)
            elif flag == 'request':
                print "Request"
                break
            elif flag == 'piece':
                piece, offset = struct.unpack('!LL', data[:8])
                print repr(data[:20])
                print "Piece Index: ", piece 
                print "Offset:", offset
                #print "Length sent:",len(data[8:])
                piece_data[offset:offset+16384] = data[8:]
                if None not in piece_data:
                    print "yay! finished a piece!"
                    break
                self.s.sendall(self.make_request(index, (offset+16384), 16384))
            elif flag == 'cancel':
                print "Peer cancelled request for this piece"
        return piece_data
    
    def run(self):
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((self.ip, self.port))
            print(self.ip + ":" + str(self.port) + " connected")
            self.handshake()
            #bitfield(self.s)
            # don't need it, can't get it right, gets us kicked
        except:
            print("Couldn't connect to " + self.ip + ":" + str(self.port))
            return
        while not piece_queue.empty():
            index, now_sha = self.piece_queue.get()
            self.s.sendall(self.make_request(index, 0, 16384))
            print index
            try:
                current_piece = self.receive_loop(index)
            except:
                print "Failed connection"
                failed = index, now_sha
                self.piece_queue.task_done()
                self.piece_queue.put(failed)
                return
                #thread.exit() also works?
            current_piece = "".join(current_piece)
            piece_sha = sha.new(current_piece).digest()
            if now_sha == piece_sha:
                print "SHA1 matches for piece", index
                self.write_queue.put((index, current_piece))
                self.s.sendall(self.make_have(index))
                self.piece_queue.task_done()
            else:
                print "Failed SHA1 check :("
                failed = index, now_sha
                self.piece_queue.task_done()
                self.piece_queue.put(failed)
    
    def handshake(self):
        ''' Initiates handshake with peer '''
        msg = chr(19) + 'BitTorrent protocol' + '\x00'*8 + self.info_hash + '-PYOTR0-dfhmjb0skee6'
        print "Beginning handshake with peer"
        self.s.send(msg)
        print "Handshake sent: ", repr(msg)
        print "Handshake rcvd: %s" % repr(self.s.recv(68))
                
    def flagmsg(self):
        ''' Takes a bit off socket buffer; returns a tuple of the action and the data from a socket
            BLOCKS'''
        first  = self.s.recv(4)
        length = struct.unpack('!L', first)[0]
        id_data = self.recv_all(self.s, length)
        if id_data == '':
            return
        id = id_data[0]
        data = id_data[1:]
        id_dict1 = {'\x01': 'unchoke', '\x00': 'choke', '\x03': 'not interested', '\x02': 'interested'}
        id_dict2 = {'\x05': 'bitfield', '\x04': 'have', '\x07': 'piece', '\x06': 'request', '\x08': 'cancel'}
        if id in id_dict1:
            return (id_dict1[id], None)
        else:
            return (id_dict2[id], data)

    def make_have(self, piece):
        ''' Constructs msg for sending a 'have piece' msg to a peer '''
        return struct.pack('!L', 5) + chr(4) + struct.pack('!L', piece)

    # the length is incorrect. why?
    def bitfield(self):
        ''' Sends bitfield '''
        length = len(pieces)/20
        print length
        msg = struct.pack('!L', length+1) + chr(5) + '\x00'*(length-1)
        self.s.send(msg)
        
    def make_request(self, piece, offset, length):
        ''' Constructs msg for requesting a block from a peer '''
        return struct.pack('!L', 13) + chr(6) + struct.pack('!LLL', piece, offset, length)        
    
    def recv_all(self, socket, expected):
        ''' Allows you to receive an expected amount off a socket '''
        data = ''
        while True:
            newdata = socket.recv(expected)
            data += newdata
            expected -= len(newdata)
            if not expected:
                break
        return data
        
        
class Writer (threading.Thread):
    ''' Thread that writes data to disk from finished pieces queue (aka write_queue) '''
    def __init__(self, write_target, write_queue, piece_length):
        threading.Thread.__init__(self)
        self.write_target = write_target
        self.write_queue = write_queue
        self.piece_length = piece_length
  
    def run(self):
        while True:
            if not self.write_queue.empty():
                index, current_piece = self.write_queue.get()
                self.write_target.seek(index*piece_length, 0)
                self.write_target.write(current_piece)
                print "wrote a piece", index
                self.write_queue.task_done()
            if piece_queue.empty():
                return


''' MAIN '''
file_load = 'kubuntu.torrent'
#file_load = 'Sapolsky.mp4.torrent'
print "Loaded", file_load
piece_queue = Queue.Queue()
metainfo = decode(file_load)
file_size = metainfo['info']['length']
info_hash = get_dict_hash(file_load)
pieces = metainfo['info']['pieces']
piece_length = metainfo['info']['piece length']
name = metainfo['info']['name']
# preallocates a file size... just one file though
write_target = open(os.getcwd() + '/' + name, 'wb+')
write_target.write(bytearray(file_size))
write_queue = Queue.Queue()

sha_list = splice_shas(pieces)
piece_list = zip([x for x in range(len(sha_list))], sha_list)
random.shuffle(piece_list)
print "Pieces currently download in random order. Shuffling into queue.."

for piece in piece_list:
    piece_queue.put(piece)



peer_list = announce(metainfo, len(sha_list), info_hash)


write_thread = Writer(write_target, write_queue, piece_length)
write_thread.setDaemon(True)
write_thread.start()
if (peer_list):
    print "Spinning up threads. Some will fail, since peer won't take two connections."
    print ""
    t = [] 
    for (ip, port) in peer_list:
        t.(Peer(piece_queue, ip, port, info_hash))
        t.setDaemon(True)
        t.start()

    piece_queue.join()
    write_thread.join()


    print "FILE FULLY DOWNLOADED (though not yet written)"
else:
    print "Couldn't find any peers to connect to."





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

