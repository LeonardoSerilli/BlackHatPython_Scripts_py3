#!/usr/bin/python3

import paramiko # https://docs.paramiko.org/en/stable/


#[!] SSH client to send commands to a server

# Sometimes it’s wise to encrypt your traffic to avoid detection. 
# A common means of doing so is to tunnel the traffic using Secure Shell (SSH). 
# But what if your target doesn’t have an SSH client (like 99.81943 percent of Windows systems)?
# Paramiko using PyCrypto gives you simple access to the SSH2 protocol.

import sys 
import getpass

# [!!!] To try online:
    # Connect to an ssh server like: https://overthewire.org/wargames/bandit/bandit0.html
    # test with: './ssh_cmd.py bandit.labs.overthewire.org 2220 bandit0 id ' with password 'bandit0'
    
# [!!!] To try locally:
    # open a ssh server:
        # 'sudo apt-get install openssh-server'
        # 'sudo systemctl enable ssh'
        # 'sudo systemctl start ssh'
        # try if it works with 'ssh userName@127.0.0.1'
        # (close it with sudo systemctl stop ssh)
    # connect with './ssh_cmd.py 127.0.0.1 22 userName id ' with your password 


def sshCmd(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    
    # Paramiko use authentication with keys instead ( or in addition) to username:password 
        # in this example will use (for simplicity) username:password for authentication
    # client.load_host_keys('/home/rorschach/.ssh/known_hosts') 
    
    # Configure the client to automatically trust unknown host keys and add them to the host key database.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  
    
    # In case of connection issues
    try:
        # we connect  
        client.connect(ip, port=port, username=user, password=passwd)
    except Exception as e:
        print(e)
        sys.exit(0)
            
    # The transport object used to perform various tasks
        # related to the connection, such as opening channels, forwarding ports, and setting up forwarding tunnels.
    # This will open a new session channel on the transport and return a Channel object, which you can use to 
        # execute commands and transfer data on the remote server.
    ssh_session = client.get_transport().open_session()
    
    # if the session is active we execute the command 
    if ssh_session.active:
        
        # OR...
        
        #ssh_session.exec_command(cmd) # execute command
        #print(ssh_session.recv(1024)) # receive output
        
        # ...OR
        
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.readlines() + stderr.readlines()
        
        if output:
           for line in output:
               print(line.strip())
        
    return 0

    
def main():    
    if(len(sys.argv[1:]) != 4):
        print("Usage: ./ssh_cmd.py  [ip] [port] [user] [cmd] ")
        print("Example ./ssh_cmd.py 11.42.0.1 2222 Rorschach id")
        sys.exit(0)
     
    ip = sys.argv[1]
    port = sys.argv[2]
    user = sys.argv[3]
    cmd = sys.argv[4]
    
    print("insert " + user + "'s password:")
    passwd = getpass.getpass()
    
    sshCmd(ip, port, user, passwd, cmd)
               
if __name__ == '__main__':
    main()