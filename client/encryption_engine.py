'''
## ENCRYPTION ENGINE 1.0
##
## This is where all the encryption magic happens.
## It uses pycrypto for most of the encryption algorithms like RSA and AES
## It is used by the m_client.py to encrypt messages and files.
##
## Author: Shimpano Mutangama
'''
import time
import sqlite3
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

class EncryptionEngine:
    
    def __init__(self):
        pass
    
    def generate_private_public_key(self):
        #Generate RSA public, private key pairs for Asymmetric encryption
        #Save them to file
        random_generator = Random.new().read
        
        private_key = RSA.generate(1024,random_generator)
        private_key_text = private_key.exportKey()
        
        public_key = private_key.publickey()
        public_key_text = public_key.exportKey()

        #in order to be saved to database \n must be escaped to \\n
        private_key_text = private_key_text.replace("\n","\\n")
        public_key_text = public_key_text.replace("\n","\\n")

        key_sql = 'INSERT INTO userkeys (username,prikey,pubkey) VALUES ("%s","%s","%s")'%("device",private_key_text,public_key_text)
        conn = sqlite3.connect("local.db")
        conn.execute(key_sql)
        conn.commit()
        conn.close()


    def generate_shared_key(self):
        #This generates a random shared (symmetric) key to use for encrypting data between users
        seed = SHA256.new()
        seed.update(Random.new().read(32))
        seed.digest()

        #Hexing produces a string longer than 32 so chop it up
        return seed.hexdigest()[:32]

    def generate_text_iv(self):
        #This generates a random iv for text using AES
        #Note: Hexed to allow JSON transmission
        seed = SHA256.new()
        seed.update(Random.new().read(32))
        return seed.hexdigest()[:16]

    def generate_file_iv(self):
        #This generates a random iv for text using AES
        #Note: Hexed to allow JSON transmission
        seed = SHA256.new()
        seed.update(Random.new().read(32))
        return seed.digest()[:16]
        

    def fetch_public_key(self):
        #Exported Encryprion keys have \n as part of the text.
        #These escape characters get removed if used raw.
        #Using \\n helps prevent this problem

        conn = sqlite3.connect('local.db')
        key_sql = 'SELECT pubkey FROM userkeys WHERE username="%s"'%("device")
        records = conn.execute(key_sql)
        key = records.fetchone()

        conn.close()
        return key[0]
    
    def fetch_private_key(self):
        #Exported Encryprion keys have \n as part of the text.
        #These escape characters get removed if used raw.
        #Using \\n helps prevent this problem

        conn = sqlite3.connect('local.db')
        key_sql = 'SELECT prikey FROM userkeys WHERE username="%s"'%("device")
        records = conn.execute(key_sql)
        key = records.fetchone()

        conn.close()
        return key[0]

    def fetch_local_shared_key(self,username):
        #Check the local database for a shared (symmentric) key for the user you're trying to contact
        conn = sqlite3.connect("local.db")
        cursor = conn.cursor()
        records = cursor.execute('SELECT username,symkey FROM sharedkeys WHERE username="%s"'%username)
        key = records.fetchone()
        conn.close()
        try:
            return key[1]
        except:
            return None

    def encrypt_key(self,shared_key,public_key):
        #This uses RSA Asymmetric encryption, so in order to transmit the shared key securely,
        #It is first encrypted with the public key of the receipient
        #In order to be read from database and use for encryptor \\n needs to be converted back to \n
        try:
            public_key = public_key.replace("\\n","\n")
        except:
            pass
        encryptor = RSA.importKey(public_key)
        
        #Raw encrypted text doesn't translate well to being sent over json so first,
        #we encode it to hex
        cipher_text = encryptor.encrypt(shared_key,32)[0].encode('hex')
        
        return cipher_text

    def decrypt_key(self,cipher_text,private_key):
        #This uses RSA Asymmetric encryption, so when someone sends this user an encrypted key,
        #It first have to be decrypted using our private key
        #In order to be read from database and use for decryptor \\n needs to be converted back to \n
        try:
            private_key = private_key.replace("\\n","\n")
        except:
            pass
        decryptor = RSA.importKey(private_key)

        #The received text has to be decoded from hex in order to be used with  decryptor
        shared_key = decryptor.decrypt(cipher_text.decode('hex'))
        return shared_key

    def encrypt_text(self,text,shared_key):
        #The AES shared key is used to encrypt message text before sending it
        random_iv = self.generate_text_iv()
        myCrypto = AES.new(shared_key,AES.MODE_CFB,bytes(random_iv))
        cipher_text = myCrypto.encrypt(text).encode('hex')
        full_text = random_iv + cipher_text
        return full_text

    def decrypt_text(self,cipher_text,shared_key):
        #The AES shared key is used to decrypt message text before it is read
        random_iv = cipher_text[:16]
        cipher_text = cipher_text[16:]
        myCrypto = AES.new(shared_key,AES.MODE_CFB,bytes(random_iv))
        cipher_text = cipher_text.decode('hex')
        plain = myCrypto.decrypt(cipher_text)
        return plain

    def encrypt_file(self,file_data,shared_key):
        #The AES shared key is used to encrypt file data text before sending it
        #Note that hexing wasnt used, raw file bytes are read and sent because
        #we're not using json to transmit files
        random_iv = self.generate_file_iv()
        myCrypto = AES.new(shared_key,AES.MODE_CFB,bytes(random_iv))
        cipher_file = myCrypto.encrypt(file_data)
        full_file = random_iv + cipher_file
        return full_file

    def decrypt_file(self,cipher_file,shared_key):
        #The AES shared key is used to decrypt file data before it is read
        #Note that dehexing wasnt used, raw file bytes are read and decrypted because
        #we're not using json to transmit files
        random_iv = cipher_file[:16]
        cipher_file = cipher_file[16:]
        #print "Cipher File: ",cipher_file
        #print "Length IV: %s"%len(random_iv)
        myCrypto = AES.new(shared_key,AES.MODE_CFB,bytes(random_iv))
        plain = myCrypto.decrypt(cipher_file)
        return plain

    def save_shared_key(self,username,key):
        #After generating or receiving a shared key, save it in the local database,
        #with the corresponding users username
        conn = sqlite3.connect("local.db")
        cursor = conn.cursor()

        #print "Saving u:%s k:%s"%(username,key)

        cursor.execute('INSERT INTO sharedkeys (username,symkey) VALUES ("%s","%s")'%(username,key))

        conn.commit()
        conn.close()
