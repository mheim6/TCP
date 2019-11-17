# Monica Heim
# Computer Networks Homework 2
# November 13, 2019


from socket import *
import argparse
import sys
import os
import re
import struct
import random
import time
from bitstring import *
from crccheck.checksum import *

# argParse
parser = argparse.ArgumentParser()
parser.add_argument("-f",
                    type=str,
                    help="Input a file ",
                    required=True)
parser.add_argument("-a",
                    type=str,
                    help="Input an ip address ",
                    required=True)
parser.add_argument("-cp",
                    type=int,
                    help="Input a client port number ",
                    required=True)
parser.add_argument("-sp",
                    type=int,
                    help="Input a server port number ",
                    required=True)
parser.add_argument('-m',
                    type=str,
                    action='store',
                    help='Input a mode for the applications operation',
                    required=False)
args = parser.parse_args()

client_Port = args.cp
server_Port = args.sp
address = args.a
mode = args.m
testFile = args.f
file = b''
openedFile = open(testFile, 'rb')


# checks port
def port_Check(port):
    if port < 5000 or port > 65535:
        print('Port not correct')
        sys.exit()
    print('Port is correct')


# checks ip
def ip_address_Check(server):
    ls = server.split('.')
    if len(ls) is not 4:
        print('IP not correct')
        sys.exit()
    for a in ls:
        if not a.isdigit():
            print('IP not correct')
            sys.exit()
        i = int(a)
        if i < 0 or i > 255:
            print('IP not correct')
            sys.exit()
    print('IP is correct')


def fCheck(fillet):
    if fillet is None:
        sys.exit()
    else:
        print("File is correct")


def mCheck(mod):
    if mod is 'r' or 'w':
        print('Mode is correct')


port_Check(server_Port)
port_Check(client_Port)
ip_address_Check(address)
fCheck(testFile)
mCheck(mode)

client_Socket = socket(AF_INET, SOCK_DGRAM)
client_Socket.bind(('', client_Port))
client_Socket.settimeout(1)


# helper function to form a packet and return it
def formPacket(source_Port, destinationPort, mode, seqNumber, ackNumber, ackBit, rstBit, synBit, finBit, windowSize,
               checksumSize, dataSeqment):
    srcPort = pack('uint:16', source_Port)
    dstPort = pack('uint:16', destinationPort)
    seqNum = pack('uint:32', seqNumber)
    ackNum = pack('uint:32', ackNumber)
    dataOffset = pack('uint:4', 5)
    reserved = pack('uint:6', 0)
    urg = pack('uint:1', 0)
    ack = pack('uint:1', ackBit)
    psh = pack('uint:1', 0)
    rst = pack('uint:1', rstBit)
    syn = pack('uint:1', synBit)
    fin = pack('uint:1', finBit)
    flags = urg + ack + psh + rst + syn + fin
    window = pack('uint:16', windowSize)
    checksum = pack('uint:16', checksumSize)
    urgPointer = pack('uint:16', 0)
    data = dataSeqment

    packet = BitArray(srcPort + dstPort + seqNum + ackNum + dataOffset + reserved + \
                      flags + window + checksum + urgPointer).bytes + data

    return packet


# unpack a packet and return its contents
def unload_packet(packet):
    source_Port = int.from_bytes(packet[0:2], byteorder='big')
    destPort = int.from_bytes(packet[2:4], byteorder='big')
    seqNum = int.from_bytes(packet[4:8], byteorder='big')
    ackNum = int.from_bytes(packet[8:12], byteorder='big')
    tempPacket = BitArray(packet[12:14]).bin
    urg = int(tempPacket[10])
    ack = int(tempPacket[11])
    psh = int(tempPacket[12])
    rst = int(tempPacket[13])
    syn = int(tempPacket[14])
    fin = int(tempPacket[15])
    window = int.from_bytes(packet[14:16], byteorder='big')
    checksum = int.from_bytes(packet[16:18], byteorder='big')
    urgPointer = int.from_bytes(packet[18:20], byteorder='big')
    data = packet[24:]
    return source_Port, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, window, checksum, urgPointer, data


# results of packet
def printPacket(packet):
    source_Port, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, \
    window, checksum, urgPointer, data = unload_packet(packet)

    print("Source Port = ", source_Port)
    print("Dest Port = ", destPort)
    print("seqNum = ", seqNum)
    print("ackNum = ", ackNum)
    print("urg = ", urg)
    print("ack = ", ack)
    print("psh = ", psh)
    print("syn = ", syn)
    print("fin = ", fin)
    print("window = ", window)
    print("checksum = ", checksum)
    print("urgPointer = ", urgPointer)
    print("data = ", data)


# handles transitions
def manage(state, packet):
    global mode
    global client_Port
    global server_Port
    global address
    global openedFile
    global serverSeqNum

    if (state == "LISTEN"):
        return state, packet


    elif (state == "SYN-SENT"):
        #  3 way handshake
        source_Port, destPort, prevSeqNum, prevAckNum, urg, ack, psh, rst, syn, fin, \
        window, checksum, urgPointer, data = unload_packet(packet)
        print("sending")
        printPacket(packet)
        print("-------------------------------------------------------------")
        client_Socket.sendto(packet, (address, server_Port))

        try:
            receivedPacket, serverAddress = client_Socket.recvfrom(1500)
        except:
            print("Failed to receive ACK to SYN-SENT")
            state = "CLOSED"
            return state, packet
        else:
            print("3 way handshake: client SYN ack/server SYN received")
            printPacket(receivedPacket)
            print("-------------------------------------------------------------")
            checksumR = int.from_bytes(Checksum16.calcbytes(receivedPacket), byteorder='big')
            print("Received packet checksum: ", checksumR)
            source_Port, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, \
            window, checksum, urgPointer, data = unload_packet(receivedPacket)
            serverSeqNum = seqNum
            print("serverSeqNum = ", serverSeqNum)

            if (ack == 1 and syn == 1 and ackNum == prevSeqNum + 1):
                print("3 way handshake complete ")
                data = openedFile.read(1448)
                packet = formPacket(client_Port, server_Port, mode, ackNum, seqNum + 1, 1, 0, 0, 0, window, 0, data)
                checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
                packet = formPacket(client_Port, server_Port, mode, ackNum, seqNum + 1, 1, 0, 0, 0, window, checksum,
                                    data)
                printPacket(packet)
                client_Socket.sendto(packet, (address, server_Port))
                print("-------------------------------------------------------------")
                try:
                    receivedPacket, serverAddress = client_Socket.recvfrom(1500)
                except:
                    print("Failed to receive packet")
                    state = "CLOSED"
                    return state, packet
                else:
                    print("packet received")
                    printPacket(receivedPacket)
                    print("-------------------------------------------------------------")
                    checksumR = int.from_bytes(Checksum16.calcbytes(receivedPacket), byteorder='big')
                    print("Received packet checksum: ", checksumR)
                    state = "ESTABLISHED"
                    return state, receivedPacket
            else:
                print(" Handshake Failed ")
                state = "CLOSED"
                return state, packet


    elif (state == "SYN-received"):
        return state, packet


    elif (state == "ESTABLISHED"):
        # 3 way handshake
        print("-------------------------------------------------------------")
        print("Entered state : ESTABLISHED")
        printPacket(packet)
        source_Port, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, \
        window, checksum, urgPointer, data = unload_packet(packet)
        data = openedFile.read(1448)
        length = len(data)
        if (length == 0):
            state = "CLOSE-WAIT"
            return state, packet
        serverSeqNum += 1
        prevData = data
        # Implementation of Packet and Checksum
        packet = formPacket(client_Port, server_Port, mode, ackNum, serverSeqNum, 1, 0, 0, 0, window, 0, data)
        checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
        packet = formPacket(client_Port, server_Port, mode, ackNum, serverSeqNum, 1, 0, 0, 0, window, checksum, data)
        printPacket(packet)
        client_Socket.sendto(packet, (address, server_Port))

        try:
            receivedPacket, serverAddress = client_Socket.recvfrom(1500)
        except:
            print("Failed to receive ACK to DATA packet")
            state = "FAILED"
            return state, packet
        else:
            checksumR = int.from_bytes(Checksum16.calcbytes(receivedPacket), byteorder='big')
            print("Received packet checksum: ", checksumR)
            source_Port, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, \
            window, checksum, urgPointer, data = unload_packet(receivedPacket)
            printPacket(receivedPacket)
            if (ack == 1):
                if (len(prevData) < 1448):
                    state = "CLOSE-WAIT"
                    return state, receivedPacket
                else:
                    state = "ESTABLISHED"
                    return state, receivedPacket
            else:
                state = "CLOSED"
                return state, packet

    elif (state == "FIN-WAIT-1"):

        len(data) == 0

        return state, packet


    elif (state == "FIN-WAIT-2"):

        return state, packet


    elif (state == "CLOSE-WAIT"):
        serverSeqNum += 1
        source_Port, destPort, seqNum, ackNum, urg, ack, psh, rst, syn, fin, \
        window, checksum, urgPointer, data = unload_packet(packet)
        packet = formPacket(client_Port, server_Port, mode, ackNum, serverSeqNum, 1, 0, 0, 1, window, 0, data)
        checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
        packet = formPacket(client_Port, server_Port, mode, ackNum, serverSeqNum, 1, 0, 0, 1, window, checksum, data)
        printPacket(packet)
        client_Socket.sendto(packet, (address, server_Port))

        state = "LAST-ACK"
        return state, packet


    elif (state == "CLOSING"):
        return state, packet


    elif (state == "LAST-ACK"):
        try:
            receivedPacket, serverAddress = client_Socket.recvfrom(1500)
        except:
            print("Failed to receive ACK , CLOSING")
            state = "CLOSED"
            return state, packet
        else:
            state = "CLOSED"
            return state, packet


    elif (state == "TIME-WAIT"):
        return state, packet


def main():
    global server_Port
    global client_Port
    state = "SYN-SENT"
    initSeqNum = random.randint(1000, 400000000)
    packet = formPacket(client_Port, server_Port, mode, initSeqNum, 0, 0, 0, 1, 0, 0, 0, b'')
    checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
    packet = formPacket(client_Port, server_Port, mode, initSeqNum, 0, 0, 0, 1, 0, 0, checksum, b'')
    print("3 way handshake : sending SYN packet")
    while (state != "CLOSED"):
        state, packet = manage(state, packet)
    client_Socket.close()
    exit(1)


if __name__ == "__main__":
    main()
