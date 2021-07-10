# raja op

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

global size,et,spit
et="<!-- /** # this encrypt is aes with sha256 key ''' **/ --> "
size=256
spit=b"or/k/3ab"
def has(key):
    
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    key=digest.finalize()
    return key
    

    
def encrypt(msg,key):
    if spit in msg:
        print("file is already encrypted")
    else:
        msg_h=has(msg)
        key=has(key)
        iv = os.urandom(16)
        padder = padding.PKCS7(size).padder()
        msg = padder.update(msg) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        #encryptor.authenticate_additional_data(msg_h)
        msg = encryptor.update(msg) 
        encryptor.finalize()
        tag=b"////////"#encryptor.tag
        
        
        return msg+spit+iv+spit+msg_h+spit+tag+spit+et.encode()


    
def decrypt(data,key):
    if not (spit in data):
        print("file is already decrypted")
    else:
        
        try:
            i=data.split(spit)
            data=i[0]
            iv=i[1]
            msg_h=i[2]
            tag=i[3]
            key=has(key)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            #decryptor.authenticate_additional_data(msg_h)
            data = decryptor.update(data)
            decryptor.finalize()
            unpadder = padding.PKCS7(size).unpadder()
            data = unpadder.update(data) + unpadder.finalize()
            return data
        except Exception as e:
            return "the key is wrong or file is corrupt",e
    
'''while 1:
    msg=input("msg")
    key=input("key")
    msg=msg.encode()
    key=key.encode()
    print(msg)
    data=encrypt(msg,key)
    print("see enc",data)
    let_see=decrypt(data,key)
    print("see dec",let_see)'''
