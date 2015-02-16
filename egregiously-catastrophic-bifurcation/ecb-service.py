#!/usr/bin/python

import os, socket, multiprocessing, sys, errno, time, random, string
from Crypto.Cipher import AES

PORTNUM = 12735
SIMULTANEOUS_CONNS = 10
FLAG = "flag{I_s33_p3ngu1ns}"

def blockify(data, blocksize=16):
  blocks = []

  for i in xrange(0, len(data), blocksize):
    blocks.append(data[i:i+blocksize])

  return blocks

def deblockify(data):
  return "".join(block for block in data)

def pkcs7(plaintext, blocksize=16):
    # rfc5652: "This padding method is well defined if and only if k is less than 256."
    if blocksize > 0xff:
        return

    length = len(plaintext)
    overflow = length % blocksize

    if overflow == 0:
        # add another block consisting of the blocksize repeated continuously
        padding = blocksize
        plaintext += chr(blocksize) * blocksize
    else:
        # pad the final incomplete block with the number of bytes necessary
        # needed to bring it up to the size of a full block
        padding = blocksize - overflow
        plaintext += chr(padding) * padding

    return plaintext

def encryptECB(plaintext, key):
  if len(plaintext) % 16 != 0:
    plaintext = pkcs7(plaintext)

  cipher = AES.new(key, AES.MODE_ECB)

  plaintextblocks = blockify(plaintext, 16)

  ciphertextblocks = []
  for plaintextblock in plaintextblocks:
    ciphertextblock = cipher.encrypt(plaintextblock)
    ciphertextblocks.append(ciphertextblock)

  return deblockify(ciphertextblocks)
    

def do_encrypt(input, clientkey):
    plaintext = os.urandom(random.randint(32,64)).encode('hex') + input + FLAG
    return encryptECB(plaintext, clientkey).encode('hex')
    pass   

def log_msg(clientinfo, msg):
    print "%s <%s:%s> %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), clientinfo[0], clientinfo[1], msg)

def client_process(s):
    clientkey = os.urandom(16)
    s.setblocking(0)
    clientinfo = s.getpeername()
    log_msg(clientinfo, "connected")
    while 1:
        time.sleep(1)
        try:
            buf = s.recv(2048).rstrip().split('\n')
            for line in buf:
                log_msg(clientinfo, "\"%s\"" % line.encode('hex'))
                s.send(do_encrypt(line, clientkey) + "\n")
        except socket.error as e:
            if e.errno is errno.EAGAIN:
                continue
            log_msg(clientinfo, "disconnected")
            s.close()
            break

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setblocking(0)
#s.bind((socket.gethostname(), PORTNUM))
s.bind(('localhost', PORTNUM))
s.listen(SIMULTANEOUS_CONNS)
print "listening on port %d..." % PORTNUM

while 1:
    try:
        (clientsocket, address) = s.accept()
        newclient = multiprocessing.Process(target = client_process, args = (clientsocket, ))
        newclient.start()
    except socket.error as e:
        if e.errno is errno.EAGAIN:
            continue
        print "bye"
        s.close()
        break
