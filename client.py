import socket
import sys
import os

def client():
    # Server Information
    # serverName = 'cc5-212-04.macewan.ca' #'School Server'
    # serverName = '127.0.0.1' #'localhost'
    serverName = input("Enter the server IP address: ").strip() #'localhost'
    serverPort = 13000 #'Port Number'
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    choice = '1'
    welcome_count = 0
    

    try:
        clientSocket.connect((serverName, serverPort))
        if welcome_count == 0:
            welcome_message = clientSocket.recv(2048)
            welcome_count += 1
            welcome_prompt = welcome_message.decode('ascii')
            # User inputs their login information
            username = input(welcome_prompt).strip()
            clientSocket.send(username.encode('ascii'))
            # Password prompt is received from the server
            password_prompt = clientSocket.recv(2048)
            password = input(password_prompt.decode('ascii')).strip()
            clientSocket.send(password.encode('ascii'))
            # Server runs a function to check if the login is correct 
            # and sends a response back to the client
        
            establishmentResponse = clientSocket.recv(2048).decode('ascii')
            # Blank response means the login was correct, 
            # otherwise the server will send an error message and terminate the connection
            if establishmentResponse != 'OK':
                print(establishmentResponse)
                termination_message = clientSocket.recv(2048).decode('ascii')
                print(termination_message)
                clientSocket.close()
                sys.exit(1)

        while True:
                try:
    
                    # Prints the menu
                    menu = clientSocket.recv(2048)
                    if not menu:
                        break
                    prompt = menu.decode('ascii')
                    choice = input(prompt).strip()
    
                    if not choice:
                        continue
    
                    clientSocket.send(choice.encode('ascii'))
    
                    if choice == '1':
                        # TBA
                        return
    
                    elif choice == '2':
                        # TBA
                        return
                        
    
                    elif choice == '3':
                        # TBA
                        return
    
                    elif choice == '4':
                        response = clientSocket.recv(2048)
                        if response:
                            print(response.decode('ascii'))
                        else:
                            print("Connection closed by server.")
                        clientSocket.close()
                        sys.exit(0)

                    else:
                        invalid_choice_message = clientSocket.recv(2048).decode('ascii')
                        print(invalid_choice_message)
                        # else: invalid choice -> loop back, server will prompt again
    
                except Exception as e:  
                    print(f"Error: {e}")
                    clientSocket.close()
                    sys.exit(1)
    
    except socket.error as e:
        print('An error occured:', e)
        clientSocket.close()
        sys.exit(1)
    
    finally:
        clientSocket.close()


client()