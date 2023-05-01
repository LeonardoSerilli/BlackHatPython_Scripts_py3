#!/usr/bin/python3
import socket
import threading

### the tcpClient.py can be used to send data after the server is running
    # as alternative nc localhost 1234 can be used as well

IP = "localhost"
PORT = 1234

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((IP, PORT))

    maxConn = 5; # the number of macimum connection allowed 
    server.listen(maxConn)
    print(f"[*] Listening on {IP}:{PORT}")

    while(True):
        
        client, addr = server.accept()
        print(f"[*] Accepted Connectipn from: {addr[0]}:{addr[1]}")
        
        # handle with threads
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

# thread handler
def handle_client(client_socket):
        # print client request
        request = client_socket.recv(1024)
        
        print(f"[*] Received {request}")
        
        # send back a packet
        client_socket.send(b"ACK")
        client_socket.close()

if __name__ == '__main__':
    main()
    
