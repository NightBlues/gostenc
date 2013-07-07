#!/usr/bin/python
# -*- coding: utf-8 -*-
from sys import argv, modules, exit
import cryptBlocks
import gost28147
import time
from reportMaker import reportMaker

makeReport = True
reporter = reportMaker("3411_"+time.strftime("%d.%b_%H.%M.%S_", time.localtime()))

def getHashFile(file):
    """        Simply reads file and calls getHash()     """
    try:
        fileContent = open(file, 'rb').read()
    except:
        raise IOError, "No such file..."
        return False
    return getHash(fileContent)

def getHash(src):
    """
        Main function - calculates hash of the given blocks.
    """
    # wtf?! 256 bit, 32 byte! its amazin
    blockLength = 32
    mess = cryptBlocks.getBlocksFromString(src, blockLength)
    checksumE = 0
    # size of message modulo 2^256
    lengthL = 0
    stepH = 0
    if makeReport:
        i = 0
    for m in mess:
        if makeReport:
            i += 1
            reporter.addBold("Variables list for block N%d "%(i))
            reporter.addList(["m = "+hex(m),"H = "+hex(stepH),"L = "+hex(lengthL),"E = "+hex(checksumE)])
        stepH = stepFunction(stepH, m)
        lengthL = (lengthL + cryptBlocks.getSizeOfBlock(m))%(2**(blockLength*8))
        checksumE += (checksumE + m)%(2**(blockLength*8))
    stepH = stepFunction(stepH, lengthL)
    stepH = stepFunction(stepH, checksumE)
    return stepH

def transformA(bl):
    """
        Transforms block bl (length 256 bit) according following rule:
        transformA(y4||y3||y2||y1) = (y1 xor y2)||y4||y3||y2
        for little-endian:
         = y2||y3||y4||(y1 xor y2)
        or:
        transformA(y1||y2||y3||y4) = y3||y2||y1||(y4 xor y3)
        goddammit:(
    """
    resBl = 0
    resBl = bl>>64
    y1 = cryptBlocks.getRight(bl, 64, True)
    y2 = cryptBlocks.getRight(resBl, 64, True)
    firstPart = y1^y2

    return firstPart<<256-64|resBl

def transformP(bl):
    """
        Transforms block bl according following rule:
        transformP(y32|y31|...|y1)=yfi(32)|yfi(31)|...|yfi(1)
    """
    fi = getFi()
    y = []
    for i in range(32):
        y.append(cryptBlocks.getRight(bl, 8, True))
        bl = cryptBlocks.cutRight(bl, 8, True)
    resBl = 0
    for i in range(1,33):
        resBl = cryptBlocks.concat(resBl, y[fi[33-i]-1], 8)
    return resBl

def transformPsi(bl):
    """
        Transforms block bl according following rule:
        transformP(y16|y15|...|y1)=(y1+y2+y3+y4+y13+y16)|y16|y15|..|y3|y2
    """
    y = []
    bl_cut = bl
    for i in range(16):
        y.append(cryptBlocks.getRight(bl_cut, 16, True))
        bl_cut = cryptBlocks.cutRight(bl_cut, 16, True)
    resBl = 0
    leftSide = y[0]^y[1]^y[2]^y[3]^y[12]^y[15]
    resBl = cryptBlocks.concat(leftSide, bl>>16, 240)
    return resBl

def getFi():
    """
        This function need for tranrformation P...Actually, it always returns
        {1: 1, 2: 9, 3: 17, 4: 25, 5: 2, 6: 10, 7: 18, 8: 26, 9: 3, 10: 11, 11: 19, 12:
        27, 13: 4, 14: 12, 15: 20, 16: 28, 17: 5, 18: 13, 19: 21, 20: 29, 21: 6, 22: 14,
         23: 22, 24: 30, 25: 7, 26: 15, 27: 23, 28: 31, 29: 8, 30: 16, 31: 24, 32: 32}
        But. In original gost 34.11-94 there is no such such array. Fi describes like this:
        fi(i+1+4(k-1)=8i+k, i=[0..3], k=[1..8]
    """
    fi = {}
    for i in range(4):
        for k in range(1,9):
            arg = i+1+(4*(k-1))
            val = (8*i)+k
            if arg <= 32 :
                fi[arg]=val
    return fi

def getFiList():
    """
        Just list representation of dictionary that returns getFi function.
         This function should always return
        [1, 9, 17, 25, 2, 10, 18, 26, 3, 11, 19, 27, 4, 12, 20, 28, 5, 13, 21, 29, 6, 14
        , 22   , 30, 7, 15, 23, 31, 8, 16, 24, 32]
    """
    fi = getFi()
    fiList = []
    for arg,val in fi.items():
        fiList.append(val)
    return fiList

def stepFunction(Hin, m):
    """
        Step function f(Hin, m)
    """
    if makeReport:
        reporter.addHeader2("stepFunction(%s,%s)"%(hex(Hin), hex(m)))
    # step1. generating keys
    C2 = 0
    C3 = 0xff00ffff000000ffff0000ff00ffff0000ff00ff00ff00ffff00ff00ff00ff00
    C4 = 0
    U = Hin
    V = m
    W = U ^ V
    K1 = transformP(W)

    U = transformA(U)^C2
    V = transformA(transformA(V))
    W = U ^ V
    K2 = transformP(W)

    U = transformA(U)^C3
    V = transformA(transformA(V))
    W = U ^ V
    K3 = transformP(W)

    U = transformA(U)^C4
    V = transformA(transformA(V))
    W = U ^ V
    K4 = transformP(W)

    if makeReport:
        reporter.addBold("Generated keys:")
        reporter.addList([hex(K1), hex(K2), hex(K3), hex(K4)])

    # step2. crypting tranformation
    Hin_cut = Hin # we need Hin for the next step, but this step cuts Hin
    h1 = cryptBlocks.getRight(Hin_cut, 64, True)
    Hin_cut = cryptBlocks.cutRight(Hin_cut, 64, True)
    h2 = cryptBlocks.getRight(Hin_cut, 64, True)
    Hin_cut = cryptBlocks.cutRight(Hin_cut, 64, True)
    h3 = cryptBlocks.getRight(Hin_cut, 64, True)
    Hin_cut = cryptBlocks.cutRight(Hin_cut, 64, True)
    h4 = cryptBlocks.getRight(Hin_cut, 64, True)
    Hin_cut = cryptBlocks.cutRight(Hin_cut, 64, True)
    s1 = gost28147.cryptBlock(h1, K1)
    s2 = gost28147.cryptBlock(h2, K2)
    s3 = gost28147.cryptBlock(h3, K3)
    s4 = gost28147.cryptBlock(h4, K4)
    S = s4
    S = cryptBlocks.concat(S, s3, 64)
    S = cryptBlocks.concat(S, s2, 64)
    S = cryptBlocks.concat(S, s1, 64)
    if makeReport:
        reporter.addBold("Crypting transformation:")
        reporter.addList([
            "gost28147(%s,%s)=%s"%(hex(h1),hex(K1),hex(s1)),
            "gost28147(%s,%s)=%s"%(hex(h2),hex(K2),hex(s2)),
            "gost28147(%s,%s)=%s"%(hex(h3),hex(K3),hex(s3)),
            "gost28147(%s,%s)=%s"%(hex(h4),hex(K4),hex(s4)),
        ])
        reporter.addBold("S="+hex(S))
    # Step 3. Shuffle transforming.
    Hout = transformPsi(S)
    for i in range(12):
        Hout = transformPsi(Hout)
    Hout = transformPsi(Hout ^ m)^Hin
    for i in range(61):
        Hout = transformPsi(Hout)
    return Hout

if __name__=="__main__":
    if len(argv) < 2:
        print "No argument passed to programm..."
        exit()
    if argv[1] == "-f":
        if len(argv) > 2:
            print hex(getHashFile(argv[2]))
        else:
            print "No file specified..."
    else :
        print hex(getHash(argv[1]))

