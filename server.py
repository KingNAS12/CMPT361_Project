import socket
import sys
import datetime
import json
import os

#user_login = "user1"
#file_information = {}
cwd = os.getcwd()

def server():
    #Server port
    serverPort = 13000 #'Adjusted to 13000 as in project specs'
    
    #Create server socket that uses IPv4 and TCP protocols 
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in server socket creation:',e)
        sys.exit(1)
    
    try:
        serverSocket.bind(('', serverPort))
    except socket.error as e:
        print('Error in server socket binding:',e)
        sys.exit(1)        
        
    # print('The server is ready to accept connections')
    #The server can only have one connection in its queue waiting for acceptance
    serverSocket.listen(1)
    print("Server Successfully Established")
    logins = parse_users()

    welcome_count = 0

    while True:
            try:
                #Server accepts client connection
                connectionSocket, addr = serverSocket.accept()
                print(addr,'   ',connectionSocket)
                while True:
                    if welcome_count == 0:
                        connectionSocket.send('Welcome to our system.\nEnter your username: ' .encode('ascii'))
                        username = connectionSocket.recv(2048).decode('ascii')
                        connectionSocket.send('Enter your password: ' .encode('ascii'))
                        password = connectionSocket.recv(2048).decode('ascii')
                        login_attempt(logins, username, password, connectionSocket)
                        welcome_count += 1
                    connectionSocket.send(
                    "\nSelect the operation \
                    \n  1) Create and send an email \
                    \n  2) Display the inbox list \
                    \n  3) Display the email contents \
                    \n  4) Terminate the connection \
                    \n\nChoice: ".encode('ascii'))

                #Server receives client message, decode it and convert it to upper case
                    message = connectionSocket.recv(2048)
                    if not message:
                        break
                    choice = message.decode('ascii').strip()

#---------------------------------------------------------------------------------------

                    protocol_decider(choice, connectionSocket, username)

#---------------------------------------------------------------------------------------

            except socket.error as e:
                print('An error occured:',e)
                serverSocket.close() 
                sys.exit(1)        
            except:
                print('Goodbye')
                serverSocket.close() 
                sys.exit(0)
                serverSocket.close()

#---------------------------------------------------------------------------------------

# FUNCTIONS/PROTOCOLS

# PARSES THE JSON FILE AND RETURNS A DICTIONARY OF USERS AND PASSWORDS
def parse_users():
    with open('user_pass.json', 'r') as f:
        users = json.load(f)
    return users

# PLACEHOLDER FOR LOGIN ATTEMPT FUNCTION (KEY NOT YET IMPLEMENTED)
def login_attempt(logins, username, password, cSocket):
    if username in logins and logins[username] == password:
        cSocket.send('OK'.encode('ascii'))
        return
    else:
        cSocket.send('Invalid Username or Password.'.encode('ascii'))
        return protocol_4(cSocket, username, login_status=False)

def protocol_decider(choice, cSocket, username):
    if choice == '1':
        return protocol_1(cSocket)
    elif choice == '2':
        return protocol_2(cSocket)
    elif choice == '3':
        return protocol_3(cSocket)
    elif choice == '4':
        return protocol_4(cSocket, username, login_status=True)
    else:
        cSocket.send('Invalid choice. Please try again.\n'.encode('ascii'))
        return

#---------------------------------------------------------------------------------------
# CREATE EMAIL PROTOCOL
def protocol_1(cSocket):
    return

#---------------------------------------------------------------------------------------
# DISPLAY INBOX PROTOCOL
def protocol_2(cSocket):
    return

#---------------------------------------------------------------------------------------
# DISPLAY EMAIL CONTENTS PROTOCOL
def protocol_3(cSocket):
    return

#---------------------------------------------------------------------------------------
# CONNECTION TERMINATION PROTOCOL (MARCOS)
def protocol_4(cSocket, username, login_status):
    if login_status:
        cSocket.sendall(('Terminating connection with ' + username + '.').encode('ascii'))
    else:
        cSocket.sendall('Terminating.'.encode('ascii'))
    cSocket.shutdown(socket.SHUT_WR)
    cSocket.close()
    return


server()
