#@@@@
from cryptography.hazmat.primitives import hashes
import encaes
import os
import sys

def get_normal_file_name(encrypted_filename):
    return encrypted_filename.replace(encrypted_file_extenstion, '')


def get_encrypted_file_name(normal_filename):
    return normal_filename + encrypted_file_extenstion

def has(key):
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    key=digest.finalize()
    return key


def enc_folder(action):
    path=r".\test folder"
    print("work")
    for r,q,f in os.walk(path):
        for q in f:
            path =os.path.join(r,q)
            print("Processing " + str(path))
            if action == "encrypt":
                enc(path)
            else:
                dec(path)
            
def enc(path):
    msg=b""
    with open(path,'rb')as q:
        msg=q.read()
        print(has(msg))
        red=encaes.encrypt(msg,key.encode())
    with open(path,'wb')as r:
        r.write(red)
    print("reading file again for checking")
    with open(path,'rb')as q:
        msg=q.read()
        print(has(msg))
    
def dec(path):
    print("reading file again for checking")
    with open(path,'rb')as q:
        msg=q.read()
        print(has(msg))
    with open(path,'rb')as q:
        data=q.read()
        red=encaes.decrypt(data,key.encode())
        print(has(red))
    with open(path,'wb')as r:
        r.write(red)

    

n=int(input("Enter Action, 1 for encrypt 2 for decrypt\n"))
if n == 1:
    ACTION="encrypt"
elif n == 2:
     ACTION="decrypt"
else:
    ACTION = None
    print("Invalid Action")
    sys.exit()
key = input("Enter New password for encryption and old password for decryption\n")

enc_folder(ACTION)
