# Monica Heim
# Computer Network Homework #2
# November 13,2019

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
parser.add_argument("-f", help="Input a file ", required=True)
parser.add_argument("-a", help="Input an IP Address ", required=True)
parser.add_argument("-cp", help="Input a client port number ", required=True)
parser.add_argument("-sp", help="Input a server port number ", required=True)
parser.add_argument("-m", help="Input a mode for the applications operation", required=False)
args = parser.parse_args()

client_port = int(args.cp)
server_port = int(args.sp)
address = args.a
mode = "write"
testFile = args.f
file = b''
openedFile = open(testFile, 'rb')


# checks port
def is_port_correct(port):
    if port < 5000 or port > 65535:
        print('Port not correct')
        sys.exit()
    print('Port is correct')


def is_port_correct(server):
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


if server_port != 0:
    is_port_correct(server_port)

if client_port != 0:
    is_port_correct(client_port)

if address != 0:
    is_port_correct(address)

client_socket = socket(AF_INET, SOCK_DGRAM)
client_socket.bind(('', client_port))
client_socket.settimeout(0.5)


# forms a packet and the it returns it
def build_packet(source_port, destination_port, mode, seq_num, ack_num, ack_bit, rst_bit, syn_bit, fin_pack,
                 window_size, checksum_size, data_seqment):
    srcPort = pack('uint:16', source_port)
    dstPort = pack('uint:16', destination_port)
    seqNum = pack('uint:32', seq_num)
    ack_number = pack('uint:32', ack_num)
    dataOffset = pack('uint:4', 5)
    reserved = pack('uint:6', 0)
    urg = pack('uint:1', 0)
    ack = pack('uint:1', ack_bit)
    psh = pack('uint:1', 0)
    rst = pack('uint:1', rst_bit)
    syn = pack('uint:1', syn_bit)
    fin = pack('uint:1', fin_pack)
    flags = urg + ack + psh + rst + syn + fin
    window = pack('uint:16', window_size)
    checksum = pack('uint:16', checksum_size)
    urgPointer = pack('uint:16', 0)
    data = data_seqment
    packet = BitArray(srcPort + dstPort + seqNum + ack_number + dataOffset + reserved + \
                      flags + window + checksum + urgPointer).bytes + data
    return packet


# unpack a packet and return its contents
def unPack(packet):
    source_port = int.from_bytes(packet[0:2], byteorder='big')
    destination_port = int.from_bytes(packet[2:4], byteorder='big')
    seqNum = int.from_bytes(packet[4:8], byteorder='big')
    ack_number = int.from_bytes(packet[8:12], byteorder='big')
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

    return source_port, destination_port, seqNum, ack_number, urg, ack, psh, rst, syn, fin, window, checksum, urgPointer, data


# results of packet
def printPacket(packet):
    source_port, destination_port, seqNum, ack_number, urg, ack, psh, rst, syn, fin, \
    window, checksum, urgPointer, data = unPack(packet)

    print("Source Port = ", source_port)
    print("Dest Port = ", destination_port)
    print("seqNum = ", seqNum)
    print("ackNum = ", ack_number)
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
def transitions(state, packet):
    global mode
    global client_port
    global server_port
    global address
    global openedFile
    global serverSeqNum

    if (state == "LISTENING"):
        return state, packet

    elif (state == "SYN SENT"):
        # 3 way handhshake
        source_port, destination_port, prevSeqNum, prevAckNum, urg, ack, psh, rst, syn, fin, \
        window, checksum, urgPointer, data = unPack(packet)
        print("sending")
        printPacket(packet)
        print("-----------------------------------------------------------------------------------------------------")
        client_socket.sendto(packet, (address, server_port))

        try:
            recievedPacket, serverAddress = client_socket.recvfrom(1500)
        except:
            print("Failed to recieve ACK to SYN-SENT")
            state = "CLOSED"
            return state, packet
        else:
            print("3 way handshake: client SYN ACK/server SYN Recieved")
            printPacket(recievedPacket)
            print(
                "-----------------------------------------------------------------------------------------------------")
            source_port, destination_port, seqNum, ack_number, urg, ack, psh, rst, syn, fin, \
            window, checksum, urgPointer, data = unPack(recievedPacket)
            serverSeqNum = seqNum
            print("serverSeqNum = ", serverSeqNum)

            if (ack == 1 and syn == 1 and ack_number == prevSeqNum + 1):
                print("3 Way Handshake Completed!)
                data = openedFile.read(1448)
                packet = build_packet(client_port, server_port, mode, ack_number, seqNum + 1, 1, 0, 0, 0, window, 0,
                                      data)
                checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
                packet = build_packet(client_port, server_port, mode, ack_number, seqNum + 1, 1, 0, 0, 0, window,
                                      checksum, data)
                printPacket(packet)
                client_socket.sendto(packet, (address, server_port))
                print(
                    "-----------------------------------------------------------------------------------------------------")
                try:
                    recievedPacket, serverAddress = client_socket.recvfrom(1500)
                except:
                    print("Failed to Recieve Packet")
                    state = "CLOSED"
                    return state, packet
                else:
                    print("Packet Recieved")
                    printPacket(recievedPacket)
                    print(
                        "-----------------------------------------------------------------------------------------------------")
                    state = "ESTABLISHED"
                    return state, recievedPacket
            else:
                print("Failed Handshake")
                state = "CLOSED"
                return state, packet


    elif (state == "SYN RECIEVED"):
        return state, packet


    elif (state == "ESTABLISHED"):
        # 3-way handshake step 3
        print("-----------------------------------------------------------------------------------------------------")
        print("Entered state ESTABLISHED")
        printPacket(packet)
        source_port, destination_port, seqNum, ack_number, urg, ack, psh, rst, syn, fin, \
        window, checksum, urgPointer, data = unPack(packet)
        data = openedFile.read(1448)
        length = len(data)
        if (length == 0):
            state = "CLOSE-WAIT"
            return state, packet
        serverSeqNum += 1
        prevData = data

        # Implementation of Packet and Checksum
        packet = build_packet(client_port, server_port, mode, ack_number, serverSeqNum, 1, 0, 0, 0, window, 0, data)
        checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
        packet = build_packet(client_port, server_port, mode, ack_number, serverSeqNum, 1, 0, 0, 0, window, checksum,
                              data)
        printPacket(packet)

        # Sends data pckt to the server
        client_socket.sendto(packet, (address, server_port))
        try:
            recievedPacket, serverAddress = client_socket.recvfrom(1500)
        except:
            print("Failed to recieve ACK to DATA packet")
            state = "FAILED"
            return state, packet
        else:
            source_port, destination_port, seqNum, ack_number, urg, ack, psh, rst, syn, fin, \
            window, checksum, urgPointer, data = unPack(recievedPacket)
            printPacket(recievedPacket)
            if (ack == 1):
                if (len(prevData) < 1448):
                    state = "CLOSE-WAIT"
                    return state, recievedPacket
                else:
                    state = "ESTABLISHED"
                    return state, recievedPacket
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
        source_port, destination_port, seqNum, ack_number, urg, ack, psh, rst, syn, fin, \
        window, checksum, urgPointer, data = unPack(packet)
        packet = build_packet(client_port, server_port, mode, acack_numberkNum, serverSeqNum, 1, 0, 0, 1, window, 0,
                              data)
        checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
        packet = build_packet(client_port, server_port, mode, ack_number, serverSeqNum, 1, 0, 0, 1, window, checksum,
                              data)
        printPacket(packet)
        client_socket.sendto(packet, (address, server_port))

        state = "LAST-ACK"
        return state, packet


    elif (state == "CLOSING"):
        return state, packet


    elif (state == "LAST-ACK"):
        try:
            recievedPacket, serverAddress = client_socket.recvfrom(1500)
        except:
            print("Fail! Failed to recieve ACK of last packet ")
            state = "CLOSED"
            return state, packet
        else:
            state = "CLOSED"
            return state, packet


    elif (state == "TIME-WAIT"):
        return state, packet


def main():
    global server_port
    global client_port
    state = "SYN-SENT"
    initSeqNum = random.randint(1000, 400000000)
    packet = build_packet(client_port, server_port, mode, initSeqNum, 0, 0, 0, 1, 0, 0, 0, b'')
    checksum = int.from_bytes(Checksum16.calcbytes(packet), byteorder='big')
    packet = build_packet(client_port, server_port, mode, initSeqNum, 0, 0, 0, 1, 0, 0, checksum, b'')
    print("3 Way handshake: Sending SYN packet")
    while (state != "CLOSED"):
        state, packet = transitions(state, packet)
    client_socket.close()
    exit(1)


if __name__ == "__main__":
    main()
