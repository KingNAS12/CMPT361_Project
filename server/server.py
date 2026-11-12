import socket
import sys
import datetime
import json
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


MAX_TITLE_LEN = 100 # The title can have at most 100 characters.
MAX_CONTENT_LEN = 1000000 # The content can have at most 1,000,000 characters.
MAX_MESSAGE_SIZE = MAX_CONTENT_LEN + 100000 # Largest message either side will accept.
MARKER = "Content: \n" # Separates the email header from the email contents.


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
    print("The server is ready to accept connections")
    logins = parse_users()

    # welcome_count = 0
    
    # Loads the server's RSA private key (used to decrypt client logins), and exits with an error if the file is missing or invalid.
    try:
        with open('server_private.pem', 'rb') as f:
            serverPrivateKey = RSA.import_key(f.read())
    except (OSError, ValueError) as e:
        print('Could not load server_private.pem:', e)
        sys.exit(1)

    while True:
            try:
                #Server accepts client connection
                connectionSocket, addr = serverSocket.accept()
                print(addr,'   ',connectionSocket)

                try:
                    result = login_attempt(logins, connectionSocket, serverPrivateKey)
                    if (result is None):
                        continue # Wait for the next client
                    username, sym_key = result
                    
                    while True:
                        """
                        if welcome_count == 0:
                            connectionSocket.send('Welcome to our system.\nEnter your username: ' .encode('ascii'))
                            username = connectionSocket.recv(2048).decode('ascii')
                            connectionSocket.send('Enter your password: ' .encode('ascii'))
                            password = connectionSocket.recv(2048).decode('ascii')
                            login_attempt(logins, username, password, connectionSocket)
                            welcome_count += 1
                        """
                        SendMessage(connectionSocket,
                            "Select the operation:"
                            "\n  1) Create and send an email"
                            "\n  2) Display the inbox list"
                            "\n  3) Display the email contents"
                            "\n  4) Terminate the connection"
                            "\n\nchoice: ", sym_key)
                        choice = ReceiveMessage(connectionSocket, sym_key).strip()

    #---------------------------------------------------------------------------------------

                        if (protocol_decider(choice, connectionSocket, username, sym_key) == TRUE):
                            break # The connection was terminated, wait for the next client

    #---------------------------------------------------------------------------------------
                except (ConnectionError, socket.error) as e:
                    # a problem with one client does not stop the server
                    print("Connection with client lost:", e)
                    connectionSocket.close() 
                except Exception as e:
                    # Bad data from one client (e.g. a file that cannot be saved) must not stop the server either
                    print("Error while serving client:", e)
                    connectionSocket.close()
            # except socket.error as e:
            #    print('An error occured:',e)
            #    serverSocket.close() 
            #    sys.exit(1)        
            except KeyboardInterrupt:
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

def login_attempt(logins, cSocket, serverPrivateKey):
    """
    Author: 
        Marcos (original credential check)
        Nathan (RSA/AES login)
    Purpose: Logs in a client. Receives the RSA encrypted username and password, checks them and, if they are valid,
        generates the AES key, sends it to the client encrypted with the client's public key and waits for the client's "OK" confirmation.
    Parameters:
        dict logins: The known usernames and their passwords (from user_pass.json).
        socket cSocket: The socket used to communicate with the connected client.
        RsaKey serverPrivateKey: The server's private key, used to decrypt the login message.
    Pre: The parameters are valid and the client has just connected.
    Post: If the login is valid, the client has the AES key and the connection stays open.
        If it is not valid, the client is told so (unencrypted) and the connection is closed.
    Throws: ConnectionError if the receive failed, the message is too large or the confirmation could not be decrypted.
    Returns: A tuple (username, sym_key) if the login succeeded, otherwise None.
    """
    username = ""
    valid = False
    
    # Receive the login message and decrypt it with the server's private key. The message is "username\npassword".
    try:
        encrypted = ReceiveBytes(cSocket)
        info = PKCS1_OAEP.new(serverPrivateKey).decrypt(encrypted).decode('ascii')
        username, password = info.split("\n", 1)
        valid = ((username in logins) and (logins[username] == password))
    except (ValueError, UnicodeDecodeError):
        pass # Could not be decrypted/parsed: treated as an invalid login
    
    # User is valid. Now get their public key on the server, which is used to send the AES key.
    if (valid):
        try:
            with open(username + "_public.pem", 'rb') as f:
                clientPublicKey = RSA.import_key(f.read())
        except (OSError, ValueError) as e:
            print("Could not load the public key of " + username + ":", e)
            valid = False
    
    # Invalid login: tell the client (unencrypted), print the message on the server screen and close the connection.
    if (not valid):
        SendMessage(cSocket, 'Invalid username or password')
        print("The received client information: " + username + " is invalid (Connection Terminated).")
        cSocket.close()
        return None
 
    # Generate the 256 bit AES key and send it encrypted with the client's public key
    sym_key = get_random_bytes(32)
    SendBytes(cSocket, PKCS1_OAEP.new(clientPublicKey).encrypt(sym_key))
    print("Connection Accepted and Symmetric Key Generated for client: " + username)
 
    # The client confirms it received the key by sending "OK" encrypted with it
    if (ReceiveMessage(cSocket, sym_key) != "OK"):
        print("Client " + username + " did not confirm the symmetric key (Connection Terminated).")
        cSocket.close()
        return None
    return (username, sym_key)

# Runs the subprotocol the client chose. Returns 'DONE' if the connection was terminated, otherwise None.
def protocol_decider(choice, cSocket, username, sym_key = None):
    if choice == '1':
        protocol_1(cSocket, username, sym_key)
    elif choice == '2':
        protocol_2(cSocket)
    elif choice == '3':
        protocol_3(cSocket)
    else:
        # Section E.6d: any other choice (including 4) is the termination subprotocol
        protocol_4(cSocket, username)
        return 'DONE'
    return None


#---------------------------------------------------------------------------------------
# CREATE EMAIL PROTOCOL
def protocol_1(connectionSocket:object, username:str, sym_key:bytes):
    """
    Author: Nathan
    Purpose: Server side of the sending email subprotocol. Receives an email from the client, checks it, and saves it in each destination's folder.
    Parameters:
        socket connectionSocket: The socket used to communicate with the connected client.
        str username: The username of the connected (logged in) client.
        bytes sym_key: The AES key shared with this client. 
    Pre: The parameters are valid and the client chose operation 1 from the menu.
    Post: If the email is valid, it is saved as [source]_[title].txt in each valid destination's folder.
    Throws: ConnectionError if the receive failed.
    Returns: None
    """
    # Ask the client to send the email.
    SendMessage(connectionSocket, "Send the email", sym_key)
    # Receive the complete email.
    email = ReceiveMessage(connectionSocket, sym_key)
    # Check the email and get its fields. Reject it if it is not valid.
    fields = ValidateEmail(email, username)
    if (fields == None):
        return
    sender, destinations, title, contentLength, content = fields
    # Print the required message on the server screen.
    print("An email from " + sender + " is sent to " + ";".join(destinations) + " has a content length of " + str(contentLength) + " .")
    savedEmail = SaveEmail(sender, destinations, title, contentLength, content)
 
def ValidateEmail(email:str, username:str):
    """
    Author: Nathan
    Purpose: Checks that a received email follows the email format specifications.
    Parameters:
        str email: The full email text received from the client.
        str username: The username of the connected client.
    Pre: The parameters are valid.
    Post: Prints the reason on the server screen if the email is rejected.
    Throws: None
    Returns: A tuple (sender, destinations list, title, content length, content) or None if the email is rejected.
    """
    # Split the email into the header lines and the contents.
    header, marker, content = email.partition(MARKER)
    lines = header.split("\n")
    if ((marker == "") or (len(lines) < 4) or (not lines[0].startswith("From: ")) or (not lines[1].startswith("To: "))
            or (not lines[2].startswith("Title: ")) or (not lines[3].startswith("Content Length: "))):
        print("Email from " + username + " rejected: incorrect format.")
        return None
    sender = lines[0][len("From: "):].strip()
    toField = lines[1][len("To: "):].strip()
    title = lines[2][len("Title: "):].strip()
    try:
        contentLength = int(lines[3][len("Content Length: "):].strip())
    except ValueError:
        print("Email from " + username + " rejected: content length is not a number.")
        return None
    # The sender must be the user that is logged in on this connection.
    if (sender != username):
        print("Email from " + username + " rejected: the From field does not match the logged in user.")
        return None
    # Check the title and content lengths.
    if ((len(title) == 0) or (len(title) > MAX_TITLE_LEN)):
        print("Email from " + username + " rejected: invalid title length.")
        return None
    if ((contentLength != len(content)) or (contentLength > MAX_CONTENT_LEN)):
        print("Email from " + username + " rejected: invalid content length.")
        return None
    # Only keep the destinations that are known clients.
    knownUsers = parse_users()
    destinations = []
    for dest in toField.split(";"):
        dest = dest.strip()
        if ((dest in knownUsers) and (dest not in destinations)):
            destinations.append(dest)
        else: 
            print("User " + dest + " does not exit. Parsing through remaining destinations.") 
    if (len(destinations) == 0):
        print("Email rejected: no valid destinations.")
        return None
    return (sender, destinations, title, contentLength, content)
 
def SaveEmail(sender:str, destinations:list, title:str, contentLength:int, content:str):
    """
    Author: Nathan
    Purpose: Adds the time and date received to an email and saves it in every destination's folder.
    Parameters:
        str sender: The username of the sending client.
        list destinations: The usernames of the clients that receive the email.
        str title: The email title.
        int contentLength: The number of characters in the content.
        str content: The email contents.
    Pre: The parameters are valid and the email was checked by ValidateEmail().
    Post: A file named [sender]_[title].txt is created in each destination's folder. If the destination folder does not exist, it is created. 
    Throws: None
    Returns: A string containing the full email as it was saved (with the Time and Date line).
    """
    timeReceived = str(datetime.datetime.now()) # The time and date the complete email was received.
    email = ("From: " + sender + "\n" +
             "To: " + ";".join(destinations) + "\n" +
             "Time and Date: " + timeReceived + "\n" +
             "Title: " + title + "\n" +
             "Content Length: " + str(contentLength) + "\n" +
             "Content: \n" + content)
    # Slashes are replaced to prevent injection. 
    fileName = sender + "_" + title.replace("/", "_").replace("\\", "_").replace("\x00", "_") + ".txt"
    for dest in destinations:
        folder = os.path.join(cwd, dest)
        os.makedirs(folder, exist_ok = True) # Make sure the client's folder exists.
        with open(os.path.join(folder, fileName), "w") as fp:
            fp.write(email)
    return email

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
def protocol_4(cSocket, username):
    # if login_status:
    #    cSocket.sendall(('Terminating connection with ' + username + '.').encode('ascii'))
    # else:
    #    cSocket.sendall('Terminating.'.encode('ascii'))
    print('Terminating connection with ' + username + '.')
    cSocket.close()
    return

#-------------------------------------------------------------------------------------------

def SendBytes(connectionSocket:object, data:bytes):
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
 
def ReceiveBytes(connectionSocket:object):
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

def SendMessage(connectionSocket:object, message_str:str, sym_key:bytes = None):
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

def ReceiveMessage(connectionSocket:object, sym_key:bytes = None):
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



server()
