#!/usr/bin/python3
import socket

### The code is already described in the tcpClient.py, are so commented only the differences

### Open a netcat UDP listener to test this code with 'nc -ulp 1234'

target_host = "localhost"
target_port = 1234

client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# No need to connect to the host (Connectionless protocol)

# Send data with 'sendto' instead of 'send()'
client.sendto(b"Chaos Intensifies\n", (target_host, target_port)) # ! No need for byte encoding

# receive data with 'recVfrom()'
    # being connectionless must store the {ip, port} tuple to send data back
    # UDP implements a message protocol. You have to ask for enough bytes 
    # to cover the entire message or it will be dropped.
    # Its common for protocols to limit messages to 1500, 
    # the max size of a standard ethernet packet). 
data, addr = client.recvfrom(4096) 

print(data, ", received from ", addr)
