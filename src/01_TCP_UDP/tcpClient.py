#!/usr/bin/python3
import socket

### Open a netcat TCP listener to test this code with 'nc -lvnp 1234'

### Three strong assumptions ###
    # (1) Our connection will always succed
    # (2) The server expect us to send data first
    # (3) The server send us the data back in timely fashion 

target_host = "localhost"
target_port = 1234

# create a socket object  
    # AF_INET is the Internet address family for IPv4. 
    # SOCK_STREAM is the socket type for TCP,
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#connect the client
client.connect((target_host, target_port))

#send data
client.send(b"Chaos Intensifies") # ! must be bythe encoded 

# receive data
    # TCP implements a stream protocol that you can read in any sized chunk you want.
    # You could do recv(1) to get a byte at a time or recv(100000) if you want to grab large chunks.
response = client.recv(4096) # 4096 is the buffer size for the response 

print(response)