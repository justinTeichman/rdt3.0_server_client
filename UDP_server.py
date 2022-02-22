import socket
import struct
import hashlib
import signal
import sys
import selectors
import random

BUFFER_SIZE = 1024  # Size of incoming packet into socket
DATA_SIZE = 256 # Size of data in each data gram

UDP_IP = "localhost" # IP

UDP_PORT = random.randint(49152,65535) # Port

sel = selectors.DefaultSelector()
expected_seq = 1
curr_seq = 0

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
listaddr = []
users = []
filename = ''
filesize = 0
bytes_read = 0
bytes_to_read = 0

# This signal is called when control C is entered into the server
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')

    data = ('EXIT SERVER').encode()    
    size = len(data)

    sequence_number = 0
    ack = 1
    type = 1

    # packing for checksum computation
    packet_tuple = (sequence_number, type, ack, size, data)
    packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s')
    packed_data = packet_structure.pack(*packet_tuple)
    checksum =  bytes(hashlib.md5().hexdigest(), encoding="UTF-8")

    # packing for packet 
    packet_tuple = (sequence_number, type, ack, size, data, checksum)
    UDP_packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)

    sock.setblocking(True)

    # send message to everybody that is a live connection to the server
    for addr in listaddr:
        send_exit_message(addr)     # method sends message to everyone in listaddr array

    sock.setblocking(False)
    print('Server is terminating ... goodbye')
    sys.exit(0)

# This method simply packs a packet with a checksum and send the packet to a specific client
def send_exit_message(addr):
    
    sock.setblocking(True)
    data = ('EXIT SERVER').encode()
    size = len(data)

    sequence_number = 0
    ack = 1
    type = 1

    packet_tuple = (sequence_number, type, ack, size, data)
    packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s')
    packed_data = packet_structure.pack(*packet_tuple)
    checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    packet_tuple = (sequence_number, type, ack, size, data, checksum)
    UDP_packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)

    sock.sendto(UDP_packet,(addr[0], addr[1]))

    sock.setblocking(False)

# add user to the user list array 
def add_user(addr,text):
    user = text[0].strip('@:')
    if(user not in users):
        listaddr.append(addr)
        users.append(user)

# remove a user user list array 
def remove_user(addr,text):
    user = text[0].strip('@:')
    listaddr.remove(addr)
    users.remove(user)

# take an unformated string with null bytes and format it
def format_message(message,size):
    new_message = message[:size]
    return new_message

# packs packet with data and checksum and sends back to client
# this method is called everytime a user sends a message to server
def send_response(addr, seq, type, ack , message):
    
    sock.setblocking(True)
    data = message.encode()
    size = len(data)
    packet_tuple = (seq,type,ack,size,data)
    packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s')
    packed_data = packet_structure.pack(*packet_tuple)
    checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    packet_tuple = (seq,type,ack,size,data,checksum)
    UDP_packet_structure = struct.Struct(f'I I I I{DATA_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)

    sock.sendto(UDP_packet,(addr[0], addr[1]))

    sock.setblocking(False)

# when called this method reads all data packets related to a file
# this method blocks until all packets are recieved
def read_file(filename,filesize,seq_num):

    sock.setblocking(True)
    
    print(f'Reading {filename}')        # File name for reading
    print(f'File Size: {filesize}')     # File size for reading

    bytes_read = 0
    bytes_to_read = int(filesize)

    expected_seq = seq_num  # expected_seq tracks the expected sequence number of the incoming packet

    # Opens a filename under the server directory with the same name
    with open(filename, 'wb') as file_to_write:
        while (bytes_read < bytes_to_read):         
            chunk,rec_seq,ack = read_data_packet()      # reads chunk of data, return ack and sequence number
            print(f'\nExpected Data Sequence Number: {expected_seq}')
            print(f'Recieved Sequence Number: {rec_seq}')
            if(rec_seq != expected_seq):            # if the chunk had already been read, ignore it and send response message
                print('Recieved Duplicate Chunk')
            else:
                print('Recieved Chunk')
                bytes_read += len(chunk)            # add to byte counter
                file_to_write.write(chunk)          # add chunk of bytes to new file under the server
            
            if(ack != 0):
                expected_seq = (expected_seq + 1)%2 


    print('Recieved File')
    print('')

    sock.setblocking(False)

    return expected_seq

# message is called everytime the a client sends the server a message
def recieve_message(sock, mask):
    
    global filename,filesize,expected_seq


    # unpacks the data and calculates the checksum
    sock.setblocking(True)
    received_packet, addr = sock.recvfrom(BUFFER_SIZE)
    unpacker = struct.Struct(f'I I I {DATA_SIZE}s 32s')

    UDP_packet = unpacker.unpack(received_packet)

    received_sequence = UDP_packet[0]
    recieved_type = UDP_packet[1]
    received_size = UDP_packet[2]
    received_data = UDP_packet[3]
    recieved_checksum = UDP_packet[4]

    values = (received_sequence,recieved_type,received_size,received_data)
    packer = struct.Struct(f'I I I {DATA_SIZE}s')
    packed_data = packer.pack(*values)
    computed_checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    if(recieved_checksum != computed_checksum):     # if the checksums don't match request the client for another message 
        print('\nMessage Checksum Error')           
        print('Requesting another Message')
        msg = 'Packet Error'
        ack = 0
        send_response(addr,received_sequence,recieved_type,0,msg)

    else:

        # processing of the client message

        received_text = format_message(received_data.decode(),received_size).split(' ')

        message = received_data.decode()

        print(f'\nRecieved Message Sequence Number: {received_sequence}')
        print(f'Expected Sequence Number {expected_seq}')

        # if the message is a duplicate then ignore and send response back to the client
        if(received_sequence != expected_seq):
            print('Recieved Duplicate Message')
            msg = 'DUPLICATE'
            ack = 1
            send_response(addr,received_sequence,recieved_type,1,msg)

        # User has disconnected using control C
        elif(len(received_text) == 3 and received_text[1] == 'has' and received_text[2] == 'Disconnected'):
            print('User has Disconnected')
            user = received_text[0].strip('@:')
            print(f'{user} is terminating')
            remove_user(addr,received_text[0].strip('@:'))
            msg = 'EXIT'
            ack = 1
            expected_seq = (expected_seq + 1)%2
            send_response(addr,expected_seq,recieved_type,1,msg)
            
        # User has just connected to the server
        elif(len(received_text) == 2 and received_text[1] == 'Register'):
            
            # User has already registered with the server ... deny it from connected
            if((received_text[0].strip('@:')) in users and addr not in listaddr):
                print('User already Exists')
                msg = 'ABORT'
                expected_seq = (expected_seq + 1)%2
                send_response(addr,received_sequence,recieved_type,1,msg)
            
            # Add user to the newtwork
            else:
                print('Recieved Message')
                msg = 'Successful Registration'
                user = received_text[0].strip('@:')
                add_user(addr,received_text[0].strip('@:'))
                print(f'{user} is connected to the server')
                ack = 1
                expected_seq = (expected_seq + 1)%2
                send_response(addr,expected_seq,recieved_type,1,msg)

        # user wants to send file
        elif(len(received_text) == 3 and received_text[1] == '!attach'):
            print('Recieved Message')
            print('Ready to Recieve File')
            
            # send response to the client and request file size
            add_user(addr,received_text[0].strip('@:'))
            expected_seq = (expected_seq + 1)%2
            send_response(addr,received_sequence,1,1,'ATTACH')

        # user has sent the file name and file size to the server
        elif(len(received_text) == 3 and received_text[0] == 'Content-Length:'):
            print('Recieved Incoming File name and size')

            filename = received_text[1]
            filesize = received_text[2]
            
            expected_seq = (expected_seq + 1)%2
            send_response(addr,received_sequence,1,1,'SEND-FILE')
            expected_seq = read_file(filename,filesize,received_sequence)  # start reading the file from the client
        
        # user has requested to the leave the server via !exit command
        elif(len(received_text) == 2 and received_text[1].strip('\n') == '!exit'):
            print('Recieved Message')
            user = received_text[0].strip('@:')
            print(f'{user} is terminating')
            remove_user(addr,received_text[0].strip('@:'))
            msg = 'EXIT'
            expected_seq = (expected_seq + 1)%2
            send_response(addr,expected_seq,recieved_type,1,msg)
        
        # user has entered a simple command, the server will print to the screen
        else:
            
            print('Recieved Message') 
            print(received_data.decode())
            add_user(addr,received_text[0].strip('@:'))
            msg = 'Message Recieved'

            expected_seq = (expected_seq + 1)%2
            send_response(addr,received_sequence,recieved_type,1,msg)
    
    sock.setblocking(False)

# method for reading bytes from the client
def read_data_packet():

    sock.setblocking(True)
    received_packet, addr = sock.recvfrom(BUFFER_SIZE)
    unpacker = struct.Struct(f'I I I {DATA_SIZE}s 32s')

    UDP_packet = unpacker.unpack(received_packet)

    received_sequence = UDP_packet[0]
    recieved_type = UDP_packet[1]
    received_size = UDP_packet[2]
    received_data = UDP_packet[3]
    recieved_checksum = UDP_packet[4]

    values = (received_sequence,recieved_type,received_size,received_data)
    packer = struct.Struct(f'I I I {DATA_SIZE}s')
    packed_data = packer.pack(*values)
    computed_checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")


    ack = 1
    if(recieved_checksum != computed_checksum):     # message is currupt update ack field
        print('Currupt Packet')
        ack = 0

    msg = 'Response'
    data = msg.encode()
    size = len(data)

    packet_tuple = (received_sequence,1,ack,size,data)
    packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s')
    packed_data = packet_structure.pack(*packet_tuple)
    checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    packet_tuple = (received_sequence,1,ack,size,data, checksum)
    UDP_packet_structure = struct.Struct(f'I I I I{DATA_SIZE}s 32s')
    UDP_packet = UDP_packet_structure.pack(*packet_tuple)

    sock.sendto(UDP_packet, (addr[0], addr[1]))     # send response form packet recieved from client
    if(ack == 0):
        read_data_packet()      # packet is currupt, server blocks and reads new copy of packet

    sock.setblocking(False)

    return received_data,received_sequence,ack

def main():
    
    signal.signal(signal.SIGINT, signal_handler)
 
    sock.bind((UDP_IP, UDP_PORT))

    print('Will wait for client connections at port ' + str(UDP_PORT))

    sel.register(sock, selectors.EVENT_READ, recieve_message)   # I/O multiplexing only for recieve_ message method

    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)

if __name__ == '__main__':
    main()
