import struct
import client
from bitstring import *


def packet(port, mode, seqNumber, ackNumber, ackBit, rstBit, synBit, finBit, windowSize, checkSumSize, dataSeqment):
    sourcePort = pack('uint:16', port)
    destPort = pack('uint:16', port)
    seqNum = pack('uint:32', seqNumber)
    ackNum = pack('uint:32', ackNumber)
    dataOffset = pack('uint:4', 0)
    reserved = pack('uint:6', 0)
    if (mode == "read" or mode == "r"):
        urg = pack('uint:1', 0)
    elif (mode == "write" or mode == "w"):
        urg = pack('uint:1', 1)
    ack = pack('uint:1', ackBit)
    psh = pack('uint:1', 0)
    rst = pack('uint:1', rstBit)
    syn = pack('uint:1', synBit)
    fin = pack('uint:1', finBit)
    flags = urg + ack + psh + rst + syn + fin
    window = pack('uint:16', windowSize)
    checksum = pack('uint:16', checkSumSize)
    urgPointer = pack('uint:16', 0)
    options = pack('uint:24', 0)
    padding = pack('uint:8', 0)
    data = dataSeqment

    packet = BitArray(sourcePort + destPort + seqNum + ackNum + dataOffset + reserved + \
             flags + window + checksum + urgPointer + options + padding).bytes + data

    return packet

def unPack(packet):
    #unpack sourcePort
    sourcePort = int.from_bytes(packet[0:2], byteorder = 'big')
    #unpack destPort
    destPort = int.from_bytes(packet[2:4], byteorder = 'big')
    #unpack seqNum
    seqNum = int.from_bytes(packet[4:8], byteorder = 'big')
    #unpack ackNum
    ackNum = int.from_bytes(packet[8:12], byteorder = 'big')
    #create new BitArray object containing the flags and convert to binary for bit splicing
    tempPacket = BitArray(packet[12:14]).bin
    #unpack urg bit (0 == read, 1 == write)
    urg = int(tempPacket[10])
    #unpack ack bit
    ack = int(tempPacket[11])
    #unpack psh bit
    psh = int(tempPacket[12])
    #unpack rst bit
    rst = int(tempPacket[13])
    #unpack syn bit
    syn = int(tempPacket[14])
    #unpack fin bit
    fin = int(tempPacket[15])
    #unpack window
    window = int.from_bytes(packet[14:16], byteorder = 'big')
    #unpack checksum
    checksum = int.from_bytes(packet[16:18], byteorder = 'big')
    #unpack urgent pointer
    urgPointer = int.from_bytes(packet[18:20], byteorder = 'big')
    #unpack options
    options = int.from_bytes(packet[20:22], byteorder = 'big')
    #unpack padding
    padding = int.from_bytes(packet[22:24], byteorder = 'big')
    #unpack data
    data = packet[24:]

    return sourcePort, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, window, checksum, urgPointer, options, padding, data


def checksum(packet):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(packet), 2):
        try:
            w = packet[i] + packet[i+1] << 8
            s = s + w
        #if packet length is odd, exception is thrown
        except:
            w = packet[i] << 8
            s = s + w

        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);

    #complement and mask to 4 byte short
        s = ~s & 0xffff

    return s

