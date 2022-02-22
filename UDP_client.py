import socket
import struct
import signal
import hashlib
import os
import sys
import argparse
from urllib.parse import urlparse
import selectors

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

BUFFER_SIZE = 1024
DATA_SIZE = 256

UDP_IP = None
UDP_PORT = None
user = None
input = None
file = None
filesize = None
sequence_number = 0

sel = selectors.DefaultSelector()

# take an unformated string with null bytes and format it
def format_message(message,size):
    new_message = message[:size]
    return new_message

# prints a input symbol for the user
def do_prompt(skip_line=False):
    if (skip_line):
        print("")
    print("\n> ", end='', flush=True)

# sends message to the server
def send_message(msg):
    
    try:
    
        global sequence_number,file,filesize

        sock.setblocking(True)
        request = msg
        data = (request).encode()    
        size = len(data)
        type = 1

        # pack packet for sending 
        packet_tuple = (sequence_number,type,size,data)
        packet_structure = struct.Struct(f'I I I{DATA_SIZE}s')
        packed_data = packet_structure.pack(*packet_tuple)
        checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        packet_tuple = (sequence_number,type, size,data,checksum)
        UDP_packet_structure = struct.Struct(f'I I I{DATA_SIZE}s 32s')
        UDP_packet = UDP_packet_structure.pack(*packet_tuple)

        print(f'Forwarding Message Sequence Number {sequence_number}')

        sock.sendto(UDP_packet, (UDP_IP, UDP_PORT))

        sock.settimeout(4)      # timer is set

        received_packet, addr = sock.recvfrom(BUFFER_SIZE)  # exception is raised if no packet is recieved

        # upack packet from client    
        incoming_packet_structure = struct.Struct(f'I I I I {DATA_SIZE}s 32s')
        
        UDP_packet = incoming_packet_structure.unpack(received_packet)

        received_sequence = UDP_packet[0]
        recieved_type = UDP_packet[1]
        recieved_ack = UDP_packet[2]
        received_size = UDP_packet[3]
        received_data = UDP_packet[4]
        received_checksum = UDP_packet[5]

        values = (received_sequence,recieved_type,recieved_ack,received_size,received_data)
        packer = struct.Struct(f'I I I I {DATA_SIZE}s')
        packed_data = packer.pack(*values)
        computed_checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        print(f'Expected Response Sequence Number {sequence_number}')
        print(f'Sever Response Sequence Number {received_sequence}')

        # message was currupted in transmission
        if(recieved_ack == 0):
            print('Recieved NACK')
            send_message(request)

        # response message was currupted in transmission
        elif(received_checksum != computed_checksum):
            print('Response Checksum Error')
            send_message(request)

        # no errors with the packet
        else:
            received_text = format_message(received_data.decode(),received_size).split(' ')

            # server has recieved Duplicate message
            if(received_data.decode() == 'DUPLICATE'):
                print('Server Recieved Duplicate message')
                do_prompt()
            
            else:

                print('Message Recieved')
                
                # server prompts client form file and filesize information
                if(received_text[0] == 'ATTACH'):
                    words = request.strip('\n').split(' ')
                    file = words[2]
                    sequence_number = (sequence_number + 1)%2

                    # checks if the file that the user wants to send actually exist
                    if(os.path.exists(file)):
                        filesize = os.path.getsize(file)
                        msg = f'Content-Length: {file} {filesize}'
                        send_message(msg)
                    else:
                        msg = 'File Does Not Exist'
                        print('File Does Not Exist')
                        send_message(msg)

                # starts the transmission of a file
                elif(received_text[0] == 'SEND-FILE' and len(received_text) == 1):
                    send_file(file,filesize)
                    do_prompt()

                # signals that the client is ready to exit the program
                elif(received_text[0] == 'EXIT' and len(received_text) == 1):
                    print('terminating program ... goodbye')
                    msg = 'DIE'
                    sys.exit(0)
                
                # server has stopped the client from connected to the server
                elif(received_text[0] == 'ABORT'):
                    print('\nCannot Join Network ... User already Exist')
                    print('Terminating program')
                    msg = 'DIE'
                    sys.exit(0)

                # prompt user for another message
                else:
                    sequence_number = (sequence_number + 1)%2
                    do_prompt()

        sock.setblocking(False)

    except:

        # timeout exceptions
        if(msg == 'DIE'):
            sys.exit(0)

        else:
            print('Time Out')
            print('Sending Message again')
            send_message(msg)
    
# handles user control C case
def signal_handler(sig, frame):
    print('Interrupt received, shutting down ...')
    msg = f'{user} has Disconnected'
    ack = 1
    send_message(msg)

# sends a packet of data to the server
def send_data_packet(chunk):
    try:
    
        print('Sending Chunk')
        global sequence_number

        sock.setblocking(True)
        
        # pack data for sending
        
        data = chunk    
        size = len(data)
        type = 0
        
        packet_tuple = (sequence_number,type,size,data)
        packet_structure = struct.Struct(f'I I I{DATA_SIZE}s')
        packed_data = packet_structure.pack(*packet_tuple)
        checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        packet_tuple = (sequence_number,type,size,data,checksum)
        UDP_packet_structure = struct.Struct(f'I I I{DATA_SIZE}s 32s')
        UDP_packet = UDP_packet_structure.pack(*packet_tuple)

        sock.sendto(UDP_packet, (UDP_IP, UDP_PORT))

        print(f'Forwarding Data Sequence Number {sequence_number}')

        sock.settimeout(4)      # raises timeout exception if the no data is recieved

        received_packet, addr = sock.recvfrom(BUFFER_SIZE)

        # unpack data for proccessing

        unpacker = struct.Struct(f'I I I I {DATA_SIZE}s 32s')
        UDP_packet = unpacker.unpack(received_packet)

        received_sequence = UDP_packet[0]
        recieved_type = UDP_packet[1]
        recieved_ack = UDP_packet[2]
        received_size = UDP_packet[3]
        received_data = UDP_packet[4]
        received_checksum = UDP_packet[5]

        values = (received_sequence,recieved_type,recieved_ack,received_size,received_data)
        packer = struct.Struct(f'I I I I {DATA_SIZE}s')
        packed_data = packer.pack(*values)
        computed_checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

        print(f'Expected Response Sequence Number {sequence_number}')
        print(f'Sever Response Sequence Number {received_sequence}')

        # bytes are currupted
        if(recieved_ack == 0):
            print('Recieved NACK ... Sending another Message Copy')
            send_data_packet(chunk)

        # response packet is currupt
        elif(received_checksum != computed_checksum):
            print('Response Checksum Error ... Sending another Message Copy')
            send_data_packet(chunk)

        print('Chunk Recieved')
        sequence_number = (sequence_number+1)%2

        sock.setblocking(False)
    
    except:

        # handles timeout exceptions

        print('Time Out')
        print('Sending Message again')
        send_data_packet(chunk)

# sends whole file the server
def send_file(filename,filesize):
    

    sock.setblocking(True)

    print('\nStart Sending File ...')

        # Send Data to Server
    with open(filename, 'rb') as file_to_send:
        while True:
            chunk = file_to_send.read(DATA_SIZE)    # read data from file that we are sending
            if chunk:
                send_data_packet(chunk)             # send chunk if its not null
            else:
                break
    
    print('File has been Sent')

    sock.setblocking(False)

# handles control C case from user
def handle_keyboard_input(file,mask):
    global input

    line=sys.stdin.readline()
    msg = (f'@{user}: {line}')
    input = msg
    send_message(msg)

# handles message from the client
def handle_server_input(sock, mask):

    sock.setblocking(True)
    received_packet, addr = sock.recvfrom(BUFFER_SIZE)

    # unpack packet

    unpacker = struct.Struct(f'I I I I {DATA_SIZE}s 32s')
    UDP_packet = unpacker.unpack(received_packet)

    received_sequence = UDP_packet[0]
    recieved_type = UDP_packet[1]
    recieved_ack = UDP_packet[2]
    received_size = UDP_packet[3]
    received_data = UDP_packet[4]
    received_checksum = UDP_packet[5]

    values = (received_sequence,recieved_type,recieved_ack,received_size,received_data)
    packer = struct.Struct(f'I I I I {DATA_SIZE}s')
    packed_data = packer.pack(*values)
    computed_checksum =  bytes(hashlib.md5(packed_data).hexdigest(), encoding="UTF-8")

    ack = 1 
    data = ''
    size = len(data)
    type = 1

    sock.setblocking(False)

    # currupt message from server
    if(received_checksum != computed_checksum):
        print('\nMessage from Server contains Checksum Error')
        ack = 0
    else:
        # server is shutting down
        # client terminates
        print('\nSever has Disconnected ... Terminating Program')
        sys.exit(0)

    sock.setblocking(False)

def main():
    
    global UDP_IP
    global UDP_PORT
    global sequence_number
    global user

    signal.signal(signal.SIGINT, signal_handler)

    # parse args for ip and port values

    parser = argparse.ArgumentParser()
    parser.add_argument("user", help="user name for this user on the chat service")
    parser.add_argument("server", help="URL indicating server location in form of chat://host:port")
    args = parser.parse_args()

    try:
        server_address = urlparse(args.server)
        if ((server_address.scheme != 'chat') or (server_address.port == None) or (server_address.hostname == None)):
            raise ValueError
        UDP_IP = server_address.hostname
        UDP_PORT = server_address.port
    except ValueError:
        print('Error:  Invalid server.  Enter a URL of the form:  chat://host:port')
        sys.exit(1)
    user = args.user

    print('Connecting to server ...')

    data = (f'@{user}: Register')
    input = data

    send_message(data)      # connection message

    sel.register(sys.stdin,selectors.EVENT_READ, handle_keyboard_input)
    sel.register(sock, selectors.EVENT_READ,handle_server_input)

    while(True):
        events = sel.select()
        for key, mask in events:
            callback = key.data
            callback(key.fileobj, mask)

if __name__ == '__main__':
    main()