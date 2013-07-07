#!/usr/bin/python
# -*- coding: utf-8 -*-
from sys import argv, modules
import cryptBlocks
import base64
import os
from reportMaker import reportMaker
import time

reporter = reportMaker("28147_"+time.strftime("%d.%b_%H.%M.%S_", time.localtime()))
makeReport=True

blockSize = 8 # operating blocks 8 of bytes
# original gost sbox
Sbox =\
   [[ 4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3],
    [14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9],
    [ 5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11],
    [ 7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3],
    [ 6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2],
    [ 4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14],
    [13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12],
    [ 1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12]]
# cryptopro sbox
#Sbox =\
#    [[10,   4,	5,	6,	8,	1,	3,	7,	13,	12,	14,	0,	9,	2,	11,	15],
#    [5,	15,	4,	0,	2,	13,	11,	9,	1,	7,	6,	3,	12,	14,	10,	8],
#    [7,	15,	12,	14,	9,	4,	1,	0,	3,	11,	5,	2,	6,	10,	8,	13],
#    [4,	10,	7,	12,	0,	15,	2,	8,	14,	1,	6,	5,	13,	11,	9,	3],
#    [7,	6,	4,	11,	9,	12,	2,	10,	1,	8,	0,	14,	15,	13,	3,	5],
#    [7,	6,	2,	4,	13,	9,	15,	0,	10,	1,	5,	11,	8,	14,	12,	3],
#    [13,	14,	4,	1,	7,	0,	5,	10,	3,	12,	8,	15,	6,	2,	9,	11],
#    [1,	3,	10,	9,	5,	11,	4,	15,	8,	6,	7,	14,	13,	0,	2,	12]]

def cryptBlockList(mess, key, direction="enc"):
    """
        Do en(de)cryption.
    """
    # for each block
    for i in range(len(mess)):
        mess[i] = cryptBlock(mess[i], key, direction)
    return mess

def cryptBlock(mess, key, direction="enc"):
    if makeReport:
        reporter.count += 1
        reporter.openHandle()
    # adding zeros to the end of the last block
    numZerosToAdd = blockSize - cryptBlocks.getSizeOfBlock(mess)
    mess = cryptBlocks.addZeros(mess, numZerosToAdd)
    if makeReport:
        reporter.add("S-box(таблица замен):<br><table><tr><td>&nbsp;</td><td>0</td><td>1</td><td>2</td><td>3</td><td>4</td><td>5</td><td>6</td><td>7</td><td>8</td><td>9</td><td>a</td><td>b</td><td>c</td><td>d</td><td>e</td><td>f</td></tr>")
        i=1
        for l in Sbox:
            l_str =""
            for s in l:
                l_str += "<td>"+hex(s)+"</td>"
            reporter.add("<tr><td>K%d:</td> %s</tr>"%(i, l_str))
            i += 1
        reporter.add("</table>")
        reporter.addBold("Список значений переданых для (рас)шифрования блока")
        reporter.addList([hex(mess),hex(key), direction])
    key = genKeys(key)
    if not (direction == "enc"):
        key.reverse()
    if makeReport:
        reporter.addBold("Сгенерированная последовательность ключей:")
        reporter.addList([hex(x) for x in key])
    N1 = cryptBlocks.getRight(mess, 4)
    N2 = cryptBlocks.getLeft(mess, 4)
    if makeReport:
        reporter.addBold("N1=%s,<br>N2=%s"%(hex(N1), hex(N2)))
        i = 1
    # 32 times
    for k in key:
        if makeReport:
            reporter.addBold("Сеть Фейстеля, итерация %d с N1=%s, N2=%s, key=%s"%(i, hex(N1), hex(N2), hex(k)))
            i+=1
        tmp = N1
        N1 = N2^functionF(N1, k)
        N2 = tmp
        if makeReport:
            reporter.addBold("Результат итерации: N1=%s, N2=%s<br>"%(hex(N1), hex(N2)))
    mess = cryptBlocks.concat(N1, N2, 32)
    if makeReport:
        reporter.addBold("Шифрованное сообщение "+hex(mess))
    return mess

def encrypt(mess_str, key_str):
    """
        Do encryption from string and return string.
    """
    # generating key list (K1...K32)
    key = cryptBlocks.getBlockFromString(key_str)
    # splitting message to blocks
    mess = cryptBlocks.getBlocksFromString(mess_str, blockSize)
    # for enable encrypting empty message%)
    if len(mess) == 0:
        mess.append(0x00)
    return cryptBlocks.getStringFromBlocks(cryptBlockList(mess, key))

def decrypt(mess_str, key_str):
    """
        Do decryption from string and return string.
    """
    # generating key list (K1...K32)
    key = cryptBlocks.getBlockFromString(key_str)
    # splitting message to blocks
    mess = cryptBlocks.getBlocksFromString(mess_str, blockSize)
    # for enable encrypting empty message%)
    if len(mess) == 0:
        mess.append(0x00)
    return cryptBlocks.getStringFromBlocks(cryptBlockList(mess, key, "dec"))

def genKeys(key):
    """
        Generates key list K1..K32.
        Every K_j is 4 bytes(or 32 bit) long.
        We would have to just iterate for each K element.
    """
    K = []
    # K1..K8
    key_cut = key
    for i in range(8):
        K.append(cryptBlocks.getRight(key_cut, 4))
        key_cut = cryptBlocks.cutRight(key_cut, 4)
    #K9..K24
    for j in range(2):
        for i in range(8):
            K.append(K[i])
    #K25..K32
    for i in range(8):
        K.append(K[7-i])
    return K

def functionF(A, K):
    """
        The function f(Ai, Ki). Ai - righ side of the block, Ki - key.
    """
    if makeReport:
        reporter.addBold("&nbsp;&nbsp;&nbsp;шаговая функция(%s, %s)"%(hex(A), hex(K)))

    # 1. Summing modulo 2^32
#    summ = (A + K) % (2**32)
    summ = A+K
    # 0x100000000 - 2**32
    if summ > 0x100000000:
        summ = summ - 0x100000000
    if makeReport:
        reporter.add("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Сумма по модулю 2<sup>32</sup>: "+hex(summ)+"<br>")
#    summ = (A+K) - (((A+K)>>32)<<32)

    # 2. Replacing S-Box
    blocks = []
    # splitting by 4 bits. youngest bits will be blocks[0]
    for i in range(8):
        blocks.append(cryptBlocks.getRight(summ, 4, True))
        summ = cryptBlocks.cutRight(summ, 4, True)
#    blocks.reverse()
#    if makeReport:
#        reporter.addList([hex(x) for x in blocks])
    # replacing...
    blocksReplaced = blocks
    if makeReport:
        reporter.add("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Заменяем по каждые 4 бита согласно таблице замен (S-box):<br>")
    for i in range(8):
        if makeReport:
            reporter.add("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; %d. %s(%d) &rarr; %s(%d)<br>"%(i+1, hex(blocks[i]),blocks[i],hex(Sbox[i][blocks[i]]),Sbox[i][blocks[i]]))
        blocksReplaced[i] = Sbox[i][blocks[i]]
    res = cryptBlocks.getIntegerFromHalfByteArray(blocksReplaced)
    if makeReport:
        reporter.add("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;В результате замены имеем: %s<br>"%(hex(res),))
    # 3. Cycle shift 11
    res = cryptBlocks.shiftCycleLeft(res, 11,32)
    if makeReport:
        reporter.add("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Циклический сдвиг влево на 11 бит: %s<br>"%(hex(res),))
    return res



if __name__=="__main__":
#    key = "gftrjdfhgytjgdfgrtjuyrthyhgdn54n"
#    open('closed.txt', 'wb').write(encrypt(open('opened.txt', 'rb').read(), key))
#    print open('closed.txt', 'rb').read()
#    print "******************************************"
#    print decrypt(open('closed.txt', 'r').read(), key)
    mess = 0x0000000000000000
#    key = 0x733d2c20656865737474676979676120626e737320657369326c656833206d54
#    key = 0x110C733D0D166568130E7474064179671D00626E161A2065090D326C4D393320
    key = 0x80B111F3730DF216850013F1C7E1F941620C1DFF3ABAE91A3FA109F2F513B239
    if makeReport:
        reporter.add("Исходные данные:<br>блок данных: %s<br>ключ: %s<hr>Начинаем зашифровку<hr>"%(hex(mess), hex(key)))
    crmess = cryptBlock(mess, key)
    print hex(crmess)
    if makeReport:
        reporter.add("<hr>Начинаем расшифровку<hr>")
    print hex(cryptBlock(crmess, key, 'dec'))
