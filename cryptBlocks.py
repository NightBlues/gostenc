#!/usr/bin/python
import base64


def reverseBytes(bint):
    """
        This function provides little <--> big endian convertings...
    """
    return getIntegerFromByteArray(getByteArrayFromBlock(bint), False)


def getByteArrayFromString(str):
    """
         Returns byte representation of the string. This function is very important cause of lots of encodings exist
    """
    return map(ord, str)

def getStringFromBlocks(bintArr):
    """
        Returns string from list of blocks.
    """
    crMess = []
    for bl in bintArr:
        crMess = crMess + getByteArrayFromBlock(bl)
    crMessStr = ""
    for sym in crMess:
        crMessStr += chr(sym)
    return crMessStr

def getStringFromBlocksB64(bintArr):
    return base64.b64encode(getStringFromBlocks(bintArr))

def splitByteArrayToBlocks(barr, length):
    """
         Splits list of bytes to list of lists of bytes that has constant size
             barr - array of bytes
             length - count of bytes
    """
    blocks = []
    i = 0
    while len(barr) > i:
        lastEl = i+length if i+length < len(barr) else len(barr)
        blocks.append(barr[i:lastEl])
        i += length
#    # if last block smaller than length
#    countZeros = length - len(blocks[-1])
#    if countZeros > 0:
#        # part of GOST 3411 - filling last block with zeros, but not to the end - to the begining of the last block
#        blocks[-1] = [0 for x in range(countZeros)] + blocks[-1]
    return blocks

def addZeros(bint, num):
    """
        Adds num zero-bytes to the right of the block.
    """
    return bint<<(8*num)

def getIntegerFromByteArray(barr, straight_order=True):
    """
         Returns integer representation of the byte array. That means that bytes are stored in memory one by one and this can be seen like a number.
         Order in list is absolute. For example : element given by using barr[3] is the third element and has order number equal to 3.
        so:
            straight_order == False means big endian
            straight_order == True means little endian
    """
    resInt = 0x00
    if not straight_order:
        barr.reverse()
    for b in barr:
        # multiplying is faster than shifting%)
        # results of timing:
        #	 Shift:  1.81705366675
        #	 Multiply:  1.46673031124
        resInt = (resInt*0x100) + b
        #resInt = (resInt<<8) + b
    return resInt

def getIntegerFromHalfByteArray(barr):
    """
        Similar to getIntegerFromByteArray. But.
        Every element in list is 4 bits long)
    """
    resInt = 0
    for b in barr:
        resInt = (resInt<<4)|b
    return resInt



def getByteArrayFromBlock(bint):
    barr = []
    bytesC = getSizeOfBlock(bint)
    for i in range(bytesC):
#        print i, ":", hex(bint), [hex(x) for x in barr]
        # yes, right and reverse, not left. beacause of leading zero byte can spoil everith
        barr.append(getRight(bint, 1))
        bint = cutRight(bint, 1)
    barr.reverse()
#    print [hex(x) for x in barr]
    return barr

def getBlockFromString(str):
    """
        Returns block from string.
    """
    return getIntegerFromByteArray(getByteArrayFromString(str))

def getBlocksFromString(str, length):
    """
        Returns array of blocks given length.
    """
    return [getIntegerFromByteArray(x, False) for x in splitByteArrayToBlocks(getByteArrayFromString(str), length)]

def getSizeOfBlock(bint, use_bits_count = False):
    """
        Returns number of bytes, that given integer takes.
    """
    # this have to be optimized...
#    return (len(hex(bint))-2)/2
    if use_bits_count:
        res = bint.bit_length()
    else:
        res = bint.bit_length() / 8 if bint.bit_length()%8 == 0 else bint.bit_length()/8+1
    return res

#def concat(blockA, blockB):
#    """
#        Concatenates 2 blocks of bytes (stored as long integer values). A || B
#    """
#    return (blockA<<(getSizeOfBlock(blockB, True)+1))|blockB

def concat(blockA, blockB, sizeOfRightBlock=False):
    """
        Concatenates 2 blocks of bytes (stored as long integer values). A || B
        You can specify size of right block in bits to prevent lead zeros spoling
    """
    if not sizeOfRightBlock:
        return (blockA<<(getSizeOfBlock(blockB, True)+1))|blockB
    return (blockA<<sizeOfRightBlock)|blockB

def getLeft(bint, bc, use_bits_count = False):
    """
        Returns bc bytes(or bits if use_bits_count set to True) from bint. Left.
    """
    mp = 1 if use_bits_count else 8
    shiftNum = getSizeOfBlock(bint, use_bits_count)-bc
    shiftNum = 0 if shiftNum<0 else shiftNum
    return bint>>(mp*shiftNum)


def getRight(bint, bc, use_bits_count = False):
    """
        Returns bc bytes(or bits if use_bits_count set to True) from bint. Right.
    """
    mp = 1 if use_bits_count else 8
    return bint-((bint>>(mp*bc))<<(mp*bc))

def cutRight(bint, bc, use_bits_count = False):
    """
        Removes bc bytes(or bits if use_bits_count set to True) from the right side of the block.
    """
    mp = 1 if use_bits_count else 8
    return bint>>(mp*bc)

def cutLeft(bint, bc, use_bits_count = False):
    """
        Removes bc bytes(or bits if use_bits_count set to True) from the left side of the block.
    """
    mp = 1 if use_bits_count else 8
    shiftNum = mp*(getSizeOfBlock(bint, use_bits_count)-bc)
    shiftNum = 0 if shiftNum<0 else shiftNum
    return bint-((bint>>shiftNum)<<shiftNum)

def modulo(n, p):
    """
        Number n  modulo p.
        n (mod p)
    """
    if n >= p:
        return n%p
    return n

def sumModulo(A,B,m):
    """
        (a+b) mod m
    """
    return (A+B)%m

def shiftCycleRight(bint, num, size=0):
    """
        Cyclic shift right by num. You should use size param cause leading zeros can appear everywhere.
    """
    if not size:
        count=getSizeOfBlock(bint, True)
    else:
        count = size
    # when count == num it means that number is shifted whole circle - thats why modulo
    if count <= num:
        num = num % count
    return (bint>>num)|(getRight(bint, num, True)<<(count-num))

def shiftCycleLeft(bint, num, size=0):
    """
        Cyclic shift left by num. You should use size param cause leading zeros can appear everywhere.
    """
    if not size:
        count=getSizeOfBlock(bint, True)
    else:
        count = size
    # when count == num it means that number is shifted whole circle - thats why modulo
    if count <= num:
        num = num % count
    return (cutLeft(bint, num, True)<<num)|getLeft(bint, num, True)