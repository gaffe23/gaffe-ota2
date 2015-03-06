#!/usr/bin/python2

import os, socket, multiprocessing, time, random
from Crypto.Cipher import AES

# ratelimit, in seconds
RATELIMIT = 0.01

# maximum amount of time a client can stay connected, in seconds
MAX_CONN_TIME = 3 * 60

PORT_NUMBER = 12734
NUM_SIMULTANEOUS_CONNS = 50
FLAG = "flag{I_s33_p3NGu1ns}"

def blockify(data, blocksize=16):
    """break data up into blocks. default block size is 16 bytes (for AES
    128)."""

    blocks = []

    for i in xrange(0, len(data), blocksize):
        blocks.append(data[i:i+blocksize])

    return blocks

def deblockify(data):
    """take data that's been split up into blocks and concatenate the blocks
    together into one big chunk of data."""
    return "".join(block for block in data)

def pkcs7(plaintext, blocksize=16):
    """apply pkcs7 padding to a plaintext to make it a suitable input to a
    block cipher."""

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
    """encrypt with AES 128 ECB. padding is automatically applied if the length
    of the given plaintext is not a multiple of 16 bytes."""

    if len(plaintext) % 16 != 0:
        plaintext = pkcs7(plaintext)

    cipher = AES.new(key, AES.MODE_ECB)

    plaintextblocks = blockify(plaintext, 16)

    ciphertextblocks = []
    for plaintextblock in plaintextblocks:
        ciphertextblock = cipher.encrypt(plaintextblock)
        ciphertextblocks.append(ciphertextblock)

    return deblockify(ciphertextblocks)

def do_encrypt(prefix, input, clientkey):
    """encrypt a client's input, prepended with their random prefix and
    appended with the flag."""
    plaintext = prefix + input + FLAG
    return encryptECB(plaintext, clientkey).encode('hex')

def log_msg(clientinfo, msg):
    """log current time, client info, and status messages."""
    print "%s <%s:%s> %s" % (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), clientinfo[0], clientinfo[1], msg)

def client_process(s):
    """handle client connection. loop infinitely, accepting client input and
    providing the client with ECB encryptions of their input under the same key
    each time. each input will be prepended with a chunk of random data and
    appended with the flag, and then encrypted to produce the ciphertext to
    send back to the client. a new random key and prefix are generated for each
    new connection, which prevents a multi-threaded solution."""

    clientkey = os.urandom(16)
    clientinfo = s.getpeername()
    clientprefix = os.urandom(random.randint(32,64)).encode('hex')
    connstart = time.time()
    log_msg(clientinfo, "connected")

    while time.time() - connstart < MAX_CONN_TIME:
        time.sleep(RATELIMIT)
        buf = s.recv(2048).rstrip().split('\n')
        try:
            for line in buf:
                log_msg(clientinfo, "\"%s\"" % blockify(line.encode('hex'), 32))
                ciphertext = do_encrypt(clientprefix, line, clientkey)
                s.send(ciphertext + "\n")
        except:
            break

    log_msg(clientinfo, "disconnected after %f seconds" % (time.time() - connstart))
    s.close()

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((socket.gethostname(), PORT_NUMBER))
    s.listen(NUM_SIMULTANEOUS_CONNS)
    print "listening on %s:%d..." % (socket.gethostbyname(socket.gethostname()), PORT_NUMBER)

    # fork off a new process for each connection
    while 1:
        (clientsocket, address) = s.accept()
        newclient = multiprocessing.Process(target = client_process, args = (clientsocket, ))
        newclient.start()

