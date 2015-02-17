#!/usr/bin/python2

import sys, string, socket
from collections import Counter

SERVER_IP = "172.31.22.4"
SERVER_PORT = 12734

def blockify(data, blocksize=16):
    """break data up into blocks. default block size is 16 bytes (for AES
    128)."""

    blocks = []

    for i in xrange(0, len(data), blocksize):
        blocks.append(data[i:i+blocksize])

    return blocks

def test_encrypt(s, input):
    """send input to server and get back the corresponding ciphertext."""
    s.send(input + "\n")
    return s.recv(2048).rstrip()

def find_dupe_blocks(ciphertext, blocksize):
    """return a list of duplicate blocks for a ciphertext, given its block size."""
    ciphertextblocks = blockify(ciphertext, blocksize)
    dupes = [x for x, y in Counter(ciphertextblocks).items() if y > 1]
    return dupes

def has_dupes(ciphertext, blocksize):
    """tell whether the given ciphertext has duplicate blocks, given its block size."""
    return bool(find_dupe_blocks(ciphertext, blocksize))

def makeDict(s, inputstring, recoveredplaintext, targetblock, blocksize):
    """create a dictionary of ciphertexts for all possible values for the single
    character we're trying to retrieve."""

    ciphertextDict = {}

    for x in string.ascii_letters + string.punctuation + string.digits:

        # python doesn't let you concatenate a string with an empty string
        if recoveredplaintext is None:
            currentInput = inputstring + x
        else:
            currentInput = inputstring + recoveredplaintext + x

        # encrypt current input, get the target block from the resulting ciphertext, and
        # add it to the dictionary
        currentCiphertext = test_encrypt(s, currentInput)
        currentBlocks = blockify(currentCiphertext, blocksize)
        currentBlock = currentBlocks[targetblock]
        ciphertextDict[currentBlock] = x

    return ciphertextDict

if __name__ == "__main__":
    family = socket.AF_INET
    type_ = socket.SOCK_STREAM
    proto = socket.IPPROTO_TCP
    s = socket.socket(family, type_, proto)
    s.connect((SERVER_IP, SERVER_PORT))

    blocksize = 0
    inputstring = ""

    # determine block size
    defaultlen = len(test_encrypt(s, inputstring))
    newlen = 0

    # continually add a single character of padding at a time to the plaintext input
    # until the ciphertext length increases by an entire block.
    while defaultlen >= newlen:
        blocksize += 1
        inputstring = "A" * blocksize
        newlen = len(test_encrypt(s, inputstring))

    # now that we have the length of a ciphertext that is exactly a single block
    # longer than the original ciphertext, take the difference to find the block size
    blocksize = newlen - defaultlen

    # find the right amount of padding to provide in order to end up with a block
    # consisting of all padding followed by a single character of the plaintext we're
    # trying to "decrypt".
    paddingsize = blocksize * 3
    inputstring = "A" * paddingsize
    while has_dupes(test_encrypt(s, inputstring), blocksize) is True:
        paddingsize -= 1
        inputstring = "A" * paddingsize

    # we have found the correct amount of padding to use, but the padding is still
    # probably smaller than the plaintext, so add an extra block's worth of padding.
    paddingsize += (blocksize * 1)
    inputstring  = "A" * paddingsize

    # determine which block will contain the current character we're targeting. start by
    # finding the index of the first duplicate ciphertext block (which is the result of
    # pumping the plaintext full of "A" blocks).
    ciphertext = test_encrypt(s, inputstring)
    dupes = find_dupe_blocks(ciphertext, blocksize)
    blocks = blockify(ciphertext, blocksize)
    targetblock = blocks.index(dupes[0]) + 3

    recoveredplaintext = ""
    for i in xrange(0, paddingsize):
        # get the ciphertext for the block that contains all padding characters followed
        # by a single unknown character of plaintext.
        padding = "A" * (paddingsize - i)
        ciphertext = test_encrypt(s, padding)
        blocks = blockify(ciphertext, blocksize)
        currentblock = blocks[targetblock]

        # make a dictionary of ciphertext blocks corresponding to all possible values for
        # the single unknown plaintext character.
        ciphertextDict = makeDict(s, padding, recoveredplaintext, targetblock, blocksize)

        # use the dictionary to try to determine what that plaintext character actually is.
        recoveredchar = ciphertextDict.get(currentblock)

        # if the value is not present in the dictionary, assume that we've already recovered
        # all of the target plaintext, and exit.
        if recoveredchar is None:
            break

        # if we did get a legitimate value for this character, output it to the screen and
        # keep trying to read more plaintext.
        sys.stdout.write(recoveredchar)
        sys.stdout.flush()
        recoveredplaintext += recoveredchar
