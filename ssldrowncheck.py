#!/usr/bin/env python
# Created by ioef - Efthimios Iosifidis 
# Tool for checking the DROWN attack on a specific host
import socket,binascii,string,sys,csv


cipher_suites = {
'020080': 'SSL2_RC4_128_EXPORT40_WITH_MD5',
'030080': 'SSL2_RC2_CBC_128_CBC_WITH_MD5', 
'040080': 'SSL2_RC2_CBC_128_CBC_WITH_MD5',
'050080': 'SSL2_IDEA_128_CBC_WITH_MD5', 
'060040': 'SSL2_DES_64_CBC_WITH_MD5', 
'0700C0': 'SSL2_DES_192_EDE3_CBC_WITH_MD5', 
'080080': 'SSL2_RC4_64_WITH_MD5', 
}


ssl2_handshakepkt='\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'

# NULL string used as handshake challenge 
challenge = '\x00' * 32

host="XXX.XXX.XXX.XXX"

port=443


print("Performing DROWN attack check for host:%s on port:%s"%(host,port))

for cipher_id, ciphersuite in cipher_suites.iteritems():
    
    print("Currently Checking Ciphersuite:%s"%(ciphersuite))    
    
    cipher = binascii.unhexlify(cipher_id) 
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:   
        
        s.connect((host, port))		
    
    except socket.error, msg:
        print "[!] Could not connect to target host: %s" % msg
        s.close()
        sys.exit(1)    
    
        
    s.send(ssl2_handshakepkt+cipher+challenge)
    
    data =' '
    
    try: 
        data = s.recv(1)
    
    except socket.error, msg:
        s.close()   
    
        
    # TLS/SSLv3 Server Hello
    if data == '\x16':   
        print("Server version is the TLS/SSLv3. Not Vulnerable!")
    elif data == '\x15': 
        print("Received Alert Error Message")
    elif data == ' ':
        print("Didn't receive response! Exiting...")
        exit(1)
    # SSLv2 Server Hello
    else:
        data = s.recv(8)
        data = s.recv(2)
        if data == '\x00\x03': 
            print("Received Server Hello! Server is Propably Vulnerable!!!!")
        else: 
            print("Server Not Vulnerable!")
    print(" ")
    
    s.close()    
