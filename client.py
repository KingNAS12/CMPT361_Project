import socket
import sys
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

MAX_TITLE_LEN = 100 # The title can have at most 100 characters.
MAX_CONTENT_LEN = 1000000 # The content can have at most 1,000,000 characters.
MAX_MESSAGE_SIZE = MAX_CONTENT_LEN + 100000 # Largest message either side will accept.

def client():
    # Server Information
    # serverName = 'cc5-212-04.macewan.ca' #'School Server'
    # serverName = '127.0.0.1' #'localhost'
    serverName = input("Enter the server IP or name: ").strip() #'localhost'
    serverPort = 13000 #'Port Number'
    
    #Create client socket that useing IPv4 and TCP protocols 
    try:
        clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error as e:
        print('Error in client socket creation:',e)
        sys.exit(1)    
    
    # choice = '1'
    # welcome_count = 0
    

    try:
        clientSocket.connect((serverName, serverPort))
        """
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
        establishmentResponse = ReceiveMessage(clientSocket, sym_key)
        # Blank response means the login was correct, 
        # otherwise the server will send an error message and terminate the connection
        if establishmentResponse != 'OK':
            print(establishmentResponse)
            termination_message = clientSocket.recv(2048).decode('ascii')
            print(termination_message)
            clientSocket.close()
            sys.exit(1)
        """

        """ Nathan's edits
        Replaced the plain-text login above. 
        The login now follows uses key encryption.
        - The client asks for the username and password itself, so the server's welcome/prompt messages and the welcome_count flag are no longer needed.
        - The username and password are sent encrypted with the server's public key (RSA, OAEP) using SendBytes, since the encrypted data is not ASCII text.
        - The server replies with either an unencrypted "Invalid username or password" (the client prints the error and terminates) or 
            the AES key (sym_key) encrypted with this client's public key.
        - The client's private key is only loaded after the login is accepted, because an unknown client does not have one.
        - The client confirms it received sym_key by sending "OK" encrypted with it.
        All later messages (menu, choices, emails) are encrypted with sym_key.
        """

        username = input("Enter your username: ").strip()
        password = input("Enter your password: ").strip()
        try:
            with open('server_public.pem', 'rb') as f:
                serverPublicKey = RSA.import_key(f.read())
        except (OSError, ValueError) as e:
            print('Could not load server_public.pem:', e)
            clientSocket.close()
            sys.exit(1)

        # Send the username and password encrypted with the server's public key
        try:
            login = (username + "\n" + password).encode('ascii')
            SendBytes(clientSocket, PKCS1_OAEP.new(serverPublicKey).encrypt(login))
        except Exception as e:
            print("The username and password cannot be sent:", e, "\nTerminating.")
            clientSocket.close()
            sys.exit(1)
        
        # The response is either the unencrypted error or the AES key encrypted with our public key
        response = ReceiveBytes(clientSocket)
        if (response == b'Invalid username or password'):
            print("Invalid username or password.\nTerminating.")
            clientSocket.close()
            sys.exit(1)
        try:
            with open(username + '_private.pem', 'rb') as f:
                clientPrivateKey = RSA.import_key(f.read())
            sym_key = PKCS1_OAEP.new(clientPrivateKey).decrypt(response)
        except Exception as e:
            print("Could not get the symmetric key:", e, "\nTerminating.")
            clientSocket.close()
            sys.exit(1)
        SendMessage(clientSocket, "OK", sym_key)

        # Login was successful. Now get menu choice. 
        while True:
                try:
                    # Prints the menu
                    prompt = ReceiveMessage(clientSocket, sym_key)
                    choice = ""
                    while (choice not in ['1', '2', '3', '4']): 
                        choice = input(prompt).strip()
                    SendMessage(clientSocket, choice, sym_key)
    
                    if choice == '1':
                        protocol_1_client(clientSocket, username, sym_key)

                    elif choice == '2':
                        # TBA
                        pass

                    elif choice == '3':
                        # TBA
                        pass

                    elif choice == '4':
                        print("The connection is terminated with the server.")
                        clientSocket.close()
                        sys.exit(0)
    
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


#---------------------------------------------------------------------------------------

def protocol_1_client(clientSocket:object, username:str, sym_key:bytes = None):
    """
    Author: Nathan
    Purpose: Client side of the sending email subprotocol. Asks the user for the email information, builds the email and sends it to the server.
    Parameters:
        socket clientSocket: The socket used to communicate with the server.
        str username: The username of the client that is logged in.
        bytes sym_key: The AES key shared with the server (None if not encrypting).
    Pre: The parameters are valid and the client chose operation 1 from the menu.
    Post: The email is sent to the server and a confirmation is printed.
    Throws: ConnectionError if the receive failed.
    Returns: None
    """
    # Wait for the server's "Send the email" message (it is not shown to the user).
    ReceiveMessage(clientSocket, sym_key)
    destinations = GetDestinations()
    title = GetTitle()
    content = GetContent()
    # Build the email following the email message structure.
    email = ("From: " + username + "\n" +
             "To: " + destinations + "\n" +
             "Title: " + title + "\n" +
             "Content Length: " + str(len(content)) + "\n" +
             "Content: \n" + content)
    SendMessage(clientSocket, email, sym_key)
    print("The message is sent to the server.")
 
def GetDestinations():
    """
    Author: Nathan
    Purpose: Asks the user for the destination usernames.
    Parameters: None
    Pre: None
    Post: Keeps asking until at least one destination is entered.
    Throws: None
    Returns: A string of the destination usernames separated by ";".
    """
    toggle = True
    while (toggle):
        entered = input("Enter destinations (separated by ;): ")
        destinations = []
        for d in entered.split(";"):
            destination = d.strip()
            if destination != "":
                destinations.append(destination)
        if (len(destinations) > 0):
            toggle = False
        else:
            print("At least one destination is required.")
    return ";".join(destinations)
 
def GetTitle():
    """
    Author: Nathan
    Purpose: Asks the user for the email title.
    Parameters: None
    Pre: None
    Post: Keeps asking until the title is 1 to 100 ascii characters.
    Throws: None
    Returns: A string containing the title.
    """
    toggle = True
    while (toggle):
        title = input("Enter title: ")
        if ((0 < len(title) <= MAX_TITLE_LEN) and (title.isascii())):
            toggle = False
        else:
            print("The title must be 1 to " + str(MAX_TITLE_LEN) + " ascii characters.")
    return title
 
def GetContent():
    """
    Purpose: Asks the user for the email contents, either typed in or loaded from a text file.
    Parameters: None
    Pre: None
    Post: Keeps asking until the contents are at most 1,000,000 ascii characters.
    Throws: None
    Returns: A string containing the contents.
    """
    answer = ""
    while (answer != "Y" and answer != "N"):
        answer = input("Would you like to load contents from a file?(Y/N) ").strip().upper()
    toggle = True
    while (toggle):
        if (answer == "Y"):
            fileName = input("Enter filename: ").strip()
            try:
                with open(fileName, "r") as fp:
                    content = fp.read()
            except Exception as e:
                print("Could not read the file: ", e)
                continue
        else:
            content = input("Enter message contents: ")
        if ((len(content) <= MAX_CONTENT_LEN) and (content.isascii())):
            toggle = False
        else:
            print("The contents must be at most " + str(MAX_CONTENT_LEN) + " ascii characters.")
    return content


#---------------------------------------------------------------------------------------

def SendBytes(connectionSocket, data:bytes):
    """
    Author: Nathan
    Purpose: Sends raw bytes to the other side of the connection. Used for the RSA encrypted login messages.
    Parameters:
        socket connectionSocket: The socket used to communicate with the other side.
        bytes data: The bytes that must be sent (already encrypted).
    Pre: The parameters are valid and the connection is open.
    Post: The size of the data (4 bytes) followed by the data itself is sent.
    Throws: None
    Returns: None
    """
    connectionSocket.sendall(len(data).to_bytes(4, byteorder = "big") + data)
 
def ReceiveBytes(connectionSocket):
    """
    Author: Nathan
    Purpose: Receives raw bytes from the other side of the connection. Used for the RSA encrypted login messages.
    Parameters:
        socket connectionSocket: The socket used to communicate with the other side.
    Pre: The parameters are valid and the other side sends the data with a 4 byte size header (see SendBytes).
    Post: A complete message is received. The data is not decrypted or decoded.
    Throws: ConnectionError if the receive failed or the message is too large. The socket is closed in both cases.
    Returns: A bytes object containing the received data.
    """
    size = 4
    for i in range (2):
        message = bytearray()
        while (len(message) < size):
            segment = connectionSocket.recv(size-len(message))
            if (not segment):
                connectionSocket.close()
                raise ConnectionError("Recv failed - socket closed")
            message.extend(segment)
        if (i == 0):
            size = int.from_bytes(message, byteorder='big')
            if (size > MAX_MESSAGE_SIZE):
                connectionSocket.close()
                raise ConnectionError("Message is too large")
    return bytes(message)

def SendMessage(connectionSocket, message_str, sym_key = None):
    """
    Author: Nathan
    Purpose: Sends a message to the other side of the connection.
    Parameters:
        socket connectionSocket: The socket used to communicate with the other side.
        str message_str: The message that must be sent.
        bytes sym_key: The AES key. If None, the message is not encrypted.
    Pre: The parameters are valid and the message only has ascii characters.
    Post: The size of the message and the (encrypted) message are sent as a byte object.
    Throws: None
    Returns: None
    """
    message_byte = message_str.encode('ascii')
    if (sym_key != None):
        # Encrypt using AES in ECB mode. The data is padded to a multiple of the block size.
        message_byte = AES.new(sym_key, AES.MODE_ECB).encrypt(pad(message_byte, AES.block_size))
    # Create a header which is 4 bytes that represent the size of the message.
    header = len(message_byte).to_bytes(4, byteorder = "big")
    # Create the byte message which contains the header and the message.
    message_final = header + message_byte
    # Send the message
    connectionSocket.sendall(message_final)

def ReceiveMessage(connectionSocket, sym_key = None):
    """
    Author: Nathan
    Purpose: Receives a message from the other side of the connection.
    Parameters:
        socket connectionSocket: The socket used to communicate with the other side.
        bytes sym_key: The AES key. If None, the message is not decrypted.
    Pre: The parameters are valid.
    Post: A complete message is received (and decrypted).
    Throws: ConnectionError if the receive failed, the message is too large, or it could not be decrypted.
    Returns: A string containing the message.
    """
    # The message is received in two parts:
        # The first 4 bytes tell us how large the message is.
        # The second part contains the actual message.
    size = 4
    for i in range (2):
        message = bytearray()
        while (len(message) < size): # Keep receiving until we have received the number of bytes we need.
            segment = connectionSocket.recv(size-len(message)) # Ask for the remaining number of bytes needed.
            if (not segment):
                connectionSocket.close()
                raise ConnectionError("Recv failed - socket closed")
            message.extend(segment) # Append the newly received bytes to the message.
        # The first set of bytes contains the size of the actual message.
        # Convert them into an integer, and then repeat to get the actual message with this size.
        if (i == 0):
            size = int.from_bytes(message, byteorder='big')
            if (size > MAX_MESSAGE_SIZE): # Refuse unreasonably large messages.
                connectionSocket.close()
                raise ConnectionError("Message is too large")
        message = bytes(message) # Convert the mutable bytearray into an immutable byte object.
    # Decrypt once message is fully received and if sym_key exists. 
    if (sym_key != None):
        try:
            message = unpad(AES.new(sym_key, AES.MODE_ECB).decrypt(message), AES.block_size)
        except ValueError:
            raise ConnectionError("Message could not be decrypted")
    return message.decode('ascii')



client()