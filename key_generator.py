import json
import os
from Crypto.PublicKey import RSA

KEY_SIZE = 2048 # RSA key size in bits (enough for the login message and the AES key).
SERVER_NAME = "server" # Server key files: server_public.pem and server_private.pem
SERVER_DIR = "server" # Directory with server.py and user_pass.json (the server machine).
CLIENT_DIR = "client" # Directory with client.py (the client machine).
USER_FILE = os.path.join(SERVER_DIR, "user_pass.json") # File that contains usernames and passwords. 

def key_generator():
    """
    Author: Nathan
    Purpose: Generates the public/private keys of the server and of every known client in user_pass.json.
    Parameters: None
    Pre: This script is in the root directory, next to the server and client directories.
         server/user_pass.json exists.
    Post: The server and client directories contain the key files:
             server directory: server_private.pem, server_public.pem and the public key of every client.
             client directory: server_public.pem and the public and private keys of every client.
          The user is asked before any existing key file is overwritten.
    Throws: Could not read file. 
    Returns: None
    """
    try:
        usernames = GetUsernames()
    except Exception as e:
        print("Could not read " + USER_FILE + ":", e)
        return
    
    names = [SERVER_NAME]
    for username in usernames:
        names.append(username)

    # Generating new keys makes the keys already copied to other machines useless, so ask first.
    existingFiles = []
    for name in names:
        privatePath, publicPaths = GetKeyPaths(name)
        allPaths = [privatePath] + publicPaths
        for path in allPaths:
            if (os.path.exists(path)):
                existingFiles.append(path)

    if (len(existingFiles) > 0):
        print("These key files already exist:")
        for path in existingFiles:
            print("  " + path)
        answer = input("Overwrite them? (Y/N) ").strip().upper()
        if (answer != "Y"):
            print("No keys were generated.")
            return

    for name in names:
        GenerateKeyPair(name)

def GetUsernames():
    """
    Author: Nathan
    Purpose: Reads the usernames of the known clients from the server's user_pass.json file.
    Parameters: None
    Pre: server/user_pass.json exists.
    Post: None
    Throws: Error if the file could not be read.
    Returns: A list of the usernames.
    """
    with open(USER_FILE, "r") as fp:
        users = json.load(fp)
    usernames = []
    for username in users:
        usernames.append(username)
    return usernames

def GetKeyPaths(name:str):
    """
    Author: Nathan
    Purpose: Gets the paths where the keys of one name (the server or a client) are stored.
             The private key stays with its owner. The public key is stored in both directories.
    Parameters:
        str name: The name used in the key file names ("server" or a client username).
    Pre: The name is valid.
    Post: None
    Throws: None
    Returns: A tuple (private key path, list of public key paths).
    """
    if (name == SERVER_NAME):
        ownerDir = SERVER_DIR
    else:
        ownerDir = CLIENT_DIR
    privatePath = os.path.join(ownerDir, name + "_private.pem")
    publicPaths = []
    publicPaths.append(os.path.join(SERVER_DIR, name + "_public.pem"))
    publicPaths.append(os.path.join(CLIENT_DIR, name + "_public.pem"))
    return (privatePath, publicPaths)

def GenerateKeyPair(name:str):
    """
    Author: Nathan
    Purpose: Generates an RSA public/private key pair and saves it as [name]_private.pem and [name]_public.pem.
    Parameters:
        str name: The name used in the key file names ("server" or a client username).
    Pre: The server and client directories exist.
    Post: The private key is saved in its owner's directory and the public key in both directories.
    Throws: Error if a file could not be written.
    Returns: None
    """
    key = RSA.generate(KEY_SIZE)
    privateKey = key.export_key()
    publicKey = key.publickey().export_key()
    privatePath, publicPaths = GetKeyPaths(name)
    with open(privatePath, "wb") as fp:
        fp.write(privateKey)
    for path in publicPaths:
        with open(path, "wb") as fp:
            fp.write(publicKey)

    print("Generated " + name + "_public.pem and " + name + "_private.pem")



key_generator()