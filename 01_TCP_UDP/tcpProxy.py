#!/usr/bin/python3
import sys
import socket
import threading

# set the timeout for waiting incoming data before forward it
TIMEOUT = 2
# Set if you want the connection to close after the timeout 
CLOSE_AFTER_TIMEOUT = False



# [!!!] To test with NETCAT:
    # open a netcat listener 'nc -lvnp 1234"
    # Run the proxy ./tcpProxy.py 127.0.0.1 4242 127.0.0.1 1234 False 
    # Connect to the proxy with 'nc 127.0.0.1 4242' 

    # [to run this example make sure TIMEOUT=2 and CLOSE_AFTER_TIMEOUT = False]
    # [=>] Now the proxy will forward request and responses, while printing hexdumps 

# [!!!] To test with PY and NETCAT:
    # create a test.txt filled with something in a dir <DIR> 
    # open a python server 'python3 -m  http.server 1234' in <DIR>
    # Run the proxy './tcpProxy.py 127.0.0.1 4242 127.0.0.1 1234 False '
    # Connect to the proxy with 'nc 127.0.0.1 4242' and send 'GET /test.txt'

    # [!] to run this example make sure TIMEOUT=2 and CLOSE_AFTER_TIMEOUT = False
    # [!] Netcat would close the connection with the python server after a single request,
        # so in this case the example would work just once
    # [=>] Now the proxy will forward request and responses, while printing hexdumps 


# is a way to fill an array od ASCII characters from the python representation made of thre characters 'A'
    # 'A' becomes A
    # 'B' becomes B
HEX_FILTER = ''.join([ (len(repr(chr(i))) == 3) and chr(i) or '.' for i in range(256)])

# handle request
def reqst_handler(buffer):
    # implement to manipulate request
    return buffer


# handle response
def resp_handler(buffer):
    # implement to manipulate responses
    return buffer

# create an hexdump from the source
def hexdump(src, length=16, show=True):
    
    if isinstance(src,bytes):
        src=src.decode()
    
    results = list()    
    
    # loop the data word by word
    for i in range(0, len(src), length):
        
        word = str(src[i:i+length])
        # builtin a function that translate by a filter 
        printable = word.translate(HEX_FILTER) 
        
        # write in and hex string the word, all lower case (thank to ':02X').
            # ex. 'ABCDEFG' become  '41424344454647'
        hexa = ''.join([f'{ord(c):02X}' for c in word]) 
        
        # format the hexdump into 3 columns 
            # ex. hexdump("a"*40+"b"*40) output:
                # 0000 61616161616161616161616161616161                 aaaaaaaaaaaaaaaa
                # 0010 61616161616161616161616161616161                 aaaaaaaaaaaaaaaa
                # 0020 61616161616161616262626262626262                 aaaaaaaabbbbbbbb
                # 0030 62626262626262626262626262626262                 bbbbbbbbbbbbbbbb
                # 0040 62626262626262626262626262626262                 bbbbbbbbbbbbbbbb
            # the first column are the word offset in hexadecimal
        hexwidth = length*3
        results.append(f'{i:04x} {hexa:<{hexwidth}} {printable}') 
        
    if show:
        for line in results:
            print(line)
        else:
            return results

# fill the buffer with incoming data , is called in the proxy handler 
def rcv_from(connection):
    buffer = b''
    connection.settimeout(TIMEOUT)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            
            buffer += data
            
    except:
        pass
    
    return buffer

def proxy_handler(lcl_socket, rmt_host, rmt_port, rcv_first):
    
    # Acting as a client the proxy connect to the rmt host
        # the client socket is passed by args (lcl_socket)
    rmt_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rmt_socket.connect((rmt_host, rmt_port))
     
    # if receive first is set we process the incoming request and send a reply
    if(rcv_first):
        rmt_buffer = rcv_from(rmt_socket)
        if len(rmt_buffer):
            print("[<== Received %d bytes from remote." % len(rmt_buffer))
            
            # dump the received data
            hexdump(rmt_buffer)
            
            # In case we want to modify the data
            rmt_buffer = resp_handler(rmt_buffer)
            lcl_socket.send(rmt_buffer)
            print("==> Sent to local.")
            
    while True:
        # if the proxy receive data from the local client 
        lcl_buffer = rcv_from(lcl_socket)
        if len(lcl_buffer):
            print("[<== Received %d bytes from local." % len(lcl_buffer))
            
            # dump the received data
            hexdump(lcl_buffer)
            
            # In case we want to modify the data
            lcl_buffer = reqst_handler(lcl_buffer)
            rmt_socket.send(lcl_buffer)
            print("==> Sent to remote.")
            
            
        # if the proxy receive data from the remote host
        rmt_buffer = rcv_from(rmt_socket)
        if len(rmt_buffer):
            print("[<== Received %d bytes from remote." % len(rmt_buffer))
            
            # dump the received data
            hexdump(rmt_buffer)
            
            # In case we want to modify the data
            rmt_buffer = resp_handler(rmt_buffer)
            lcl_socket.send(rmt_buffer)
            print("==> Sent to local.")
        
        # if no data we close the connections 
        if (not len(lcl_buffer) or not len(rmt_buffer)) and CLOSE_AFTER_TIMEOUT :
            lcl_socket.close()
            rmt_socket.close() 
            print("[*] no more data. Closing connections.")
            break


# Handle the logic of the proxy 
def server_loop(lcl_host, lcl_port, rmt_host, rmt_port, rcv_first):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    
    try:
        server.bind((lcl_host, lcl_port))
    except Exception as e:
        print("[!!] Failed to listen on %s %d." % (lcl_host, lcl_port))
        print("check for other listening socket or correct permissions.")
        print(e)
        sys.exit(0)

    print("[*] Listening on %s %d." % (lcl_host, lcl_port))
    server.listen(5)
    while(True):
        client_socket, addr = server.accept()
        print("> Received incoming connection from %s %d" % (addr[0], addr[1]))
        
        proxyThread = threading.Thread(
                target=proxy_handler, 
                args=(client_socket, rmt_host, rmt_port, rcv_first
            ))
        
        proxyThread.start()

def main():    
    if(len(sys.argv[1:]) != 5):
        print("Usage: ./tcpProxy [localhost] [localport] ", end='')
        print("[remotehost] [remoteport] [recivefirst]")
        print("Example ./tcpProxy.py 127.0.0.1 1234 10.12.132.1 4242 True")
        sys.exit(0)
     
    lcl_host = sys.argv[1]
    lcl_port = int(sys.argv[2])
    
    rmt_host = sys.argv[3]
    rmt_port = int(sys.argv[4])
    
    rcv_first = bool(sys.argv[5])
    
    server_loop(lcl_host, lcl_port, rmt_host, rmt_port, rcv_first)
               
if __name__ == '__main__':
    main()