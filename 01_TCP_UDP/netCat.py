#!/usr/bin/python3
import sys
import socket
import threading
import shlex # lessical analyzer for shell coding
import subprocess
import argparse # https://docs.python.org/3/howto/argparse.html
import textwrap


###Examples
    # send() -> 'echo 'abc' | ./netCat.py -t 127.0.0.1 -p 1234 ' send to a netcat listener 'nc -lvnp 1234'
    # listen() -> './netCat.py -t 127.0.0.1 -p 1234 -l -c' open a shell anc connect to it with 'nc 124.0.0.1 1234'
    # './netCat.py -t 127.0.0.1 -p 1234 -l -e="cat  /etc/passwd"' execute a command, visible if connected with 'nc 127.0.0.1 1234'
    # './netCat.py -t 127.0.0.1 -p 1234 -l -u=asd.text' connect with 'nc 127.0.0.1 1234' and write to the new file on the server
    
# execute a command 
def execute(cmd):
    cmd = cmd.strip() # remove white spaces 
    # if no user input
    if not cmd:
        return
    output = subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
    return output.decode()

class NetCat:
    def __init__(self, args, buffer=None):
        self.args = args # contains the options given from command line (ex. '-t', '-p', etc..)
        self.buffer = buffer # contains the stdin 
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # check is is a listener or entablishinga a connection 
    def run(self):
        if(self.args.listen):
            self.listen() # if we are using netcat as a listener we run the relative method
        else:
            print("asd")
            self.send() # if we are connecting to a socket we have to send data

    # keep sending and rceiving data until ctrl+c
    def send(self):
        
        # connect to the target
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            # send the request
            self.socket.send(self.buffer) # in this case the buffer contains our request  
            try:
                # the double loop is used to keep looping where there's no more data
                    # so we can interrupt just by 'ctrl+c'
                while True:
                    recv_len = 1
                    response = ''
                    # loop through chunks of data while there's response data
                    while recv_len:
                        data = self.socket.recv(4096)
                        recv_len=len(data)
                        
                        response += data.decode('UTF8')
                        
                        if recv_len < 4096:
                            break
                        
                        # we write and send our new resquest
                        if response:
                            print(response)
                            buffer = input('>') # keyboard input 
                            buffer += "\n"
                            self.socket.send(buffer.encode())
                            
            except KeyboardInterrupt:
                print('User Terminated.')
                self.socket.ckise()
                sys.exit(1)

    # exactly the tcpServer.py code, is basically a server handling requests through threads
    def listen(self):
        self.socket.bind((self.args.target, self.args.port))
        max_conn = 5
        self.socket.listen(max_conn)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start();
    
    # client requests handler requests 
    def handle(self, client_socket):
           
        # Execute commands
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())
         
        # Upload data
        elif self.args.upload:
            
            # we first obtain the data ...
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                
                if data != b'\n':
                    file_buffer += data
                    print(len(file_buffer))
                else:
                    break
            
            # ...then upload a file 
            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
                
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())
            
        # initialize a shell until user interruption
        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    # you can write the command and enter new line to execute it
                    client_socket.send(b' #> ') # show a prompt 
                    
                    # read input until new line is entered
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                        
                    # execute the command and print the response
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                        
                    cmd_buffer = b''
                except Exception as e:
                    client_socket.send(b'Server killed')
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()
        
        
# main function responsible for handling command-line arguments and calling the rest of our functions.
if __name__ == '__main__':
    parser=argparse.ArgumentParser(
       description = 'BHP Net Tool',
       formatter_class = argparse.RawDescriptionHelpFormatter,
       
       # define examples
       epilog = textwrap.dedent('''Example: 
            netcat.py -t 192.16.1.108 -p 4269 -l -c # command shell
            netcat.py -t 192.16.1.108 -p 4269 -l -u = test.text # upload file
            netcat.py -t 192.16.1.108 -p 4269 -l -e\"cat /etc/passwd\" # execute command
            echo 'ABC' | ./netcat.py -t 192.16.1.108 -p 4269 # echo text on server port 4269
            netcat.py - t 192.16.1.108 -p 4269 # connect to server
            ''')
    )
    
    # define the help menù
    parser.add_argument('-c', '--command', action="store_true", help='command shell')
    parser.add_argument('-e', '--execute', help='execute specific command')
    parser.add_argument('-l', '--listen', action="store_true", help='listen')
    parser.add_argument('-p', '--port', type = int, default=4269, help='specified port')
    parser.add_argument('-t', '--target', help='specified ip')
    parser.add_argument('-u', '--upload', help='upload file')
    
    args = parser.parse_args()  

    # if we are using netcat as a listener out buffer is empty 
    if args.listen:
        buffer = ''
    else:
        buffer = sys.stdin.read()

    nc = NetCat(args, buffer.encode())
    nc.run()
