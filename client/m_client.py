'''
## MESSAGING CLIENT 1.0
## 
## This is a simple client side app that connects to the messaging server and provides End to End Encryption
## All messages tranfered between clients is indecipherable to all except communicating parties
## Users can register for accounts with the chosen server.
## You can also transfer files which will also be encrypted during transit.
## To transfer files, in the "Enter message: " prompt type "file: (filename)" without quotes,
## ...File must be within the same folder as this file (m_client.py) in order for it to work.
## 
## Messages use a json based api
##
## IMPORTANT: If you wish to have multiple accounts, you must create a separate folder for
## each user, each containing the m_client.py and encryption_engine.py files.
## ...DO NOT login to another account from the wrong account folder.
## ...This is because of how the encryption keys are stored
##
## Author: Shimpano Mutangama
'''
import socket
import threading
import json
import sqlite3
import time
import sys
from encryption_engine import EncryptionEngine
import getpass
from io import BytesIO

class Client(object):

    def __init__(self,host,port):

        self._logged_user = None
        self._remote_user_key = None
        self._logged_user_api_key = None
        
        
        self._server_tuple = (host,port)
        self.client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self._encryption_engine = EncryptionEngine()
        self._prepare_app()
        self._main_option_menu()
        self._initialize_waiting_thread()
        self._user_option_menu()

        
    def _poll_server_connection(self,server_tuple):
        #Keep trying to connect every 5 seconds until server is found and online
        while True:
            try:
                self.client_socket.connect(server_tuple)
                break
            except:
                time.sleep(5)

    def _prepare_app(self):
        #This generates the public and private keys and creates the local database
        #in SQLite
        conn = sqlite3.connect("local.db")
        cursor = conn.cursor()
        
        #Create Tables if none exist
        user_key_table_sql = "CREATE TABLE IF NOT EXISTS userkeys (id INTEGER PRIMARY KEY NOT NULL,username varchar(200),prikey varchar(2000),pubkey varchar(2000))" 
        shared_key_table_sql = "CREATE TABLE IF NOT EXISTS sharedkeys (id INTEGER PRIMARY KEY NOT NULL,username varchar(200),symkey varchar(2000))"   
        message_table_sql = "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY NOT NULL, message varchar(200), sender varchar(200), receipient varchar(200), date varchar(200))"
        cursor.execute(shared_key_table_sql)
        cursor.execute(message_table_sql)
        cursor.execute(user_key_table_sql)
        
        #Check if you have generated your private keys
        check_keys_sql = 'SELECT pubkey,prikey FROM userkeys WHERE username=?'
        record = conn.execute(check_keys_sql,("device",))
        keys = record.fetchone()
        
        if keys is not None:
            pass
        else:
            self._encryption_engine.generate_private_public_key()

        print "Done preparing app"

        conn.commit()
        conn.close()

    def _main_option_menu_header(self):

        print ""
        print "********* MESSAGING SERVICE *********"
        print "1. Register a User "
        print "2. Login a User "
        print ""
        
    def _main_option_menu(self):

        self._main_option_menu_header()
        
        while True:
            print "> ",
            menu_choice = raw_input("")

            if menu_choice == "1":
                
                print""
                username = raw_input("Choose a Username: ")
                password = getpass.getpass("Choose a Password: ")
                
                print "Connecting to Server"
                self._poll_server_connection(self._server_tuple)
                
                public_key = self._encryption_engine.fetch_public_key()
                request_json = '{"username":"%s","password":"%s","public_key":"%s","type":"registration"}'%(username,password,public_key)
                self.client_socket.sendall(request_json)
                
            
            elif menu_choice == "2":
                
                print""
                username = raw_input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                
                print "Connecting to Server"
                self._poll_server_connection(self._server_tuple)
                
                request_json = '{"username":"%s","password":"%s","type":"login"}'%(username,password)
                self.client_socket.sendall(request_json)
                
            
            response = self.client_socket.recv(1024)
            response_json = json.loads(response)

            if response_json["success"] == True:
                self._logged_user = username
                self._logged_user_api_key = response_json["api_key"]
                break
            else:
                self.client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                print""
                print response_json["reason"]
                print""
                
            
        
    def _initialize_waiting_thread(self):
        #This thread waits to receive messages from the server and other users
        t = threading.Thread(target = self._wait_for_messages)
        t.daemon = True
        t.start()

    def _wait_for_messages(self):

        try:

            while True:
                chunk = self.client_socket.recv(1024)
                response = ''

                while chunk:
                    if chunk[-2:] == "/0":
                        response+=chunk[:-2]
                        break
                    response+= chunk
                    chunk = self.client_socket.recv(1024)


                print"Response is: %s"%response
                self._handle_message_response(response)
                
        except:
            
            print"Shutting down.."
                

    def _handle_message_response(self,response):
        try:
            
            json_data = json.loads(response)
            
            if json_data["type"] == "message":

                #Handles when user receives a message
                
                sender = json_data["sender"]
                date = json_data["date"]
                message = json_data["message"]
                receipient = json_data["receipient"]
                shared_key = self._encryption_engine.fetch_local_shared_key(sender)
                decrypted_text = self._encryption_engine.decrypt_text(message,shared_key)
                
                print"\nMessage Received"
                print""
                print"From: %s"%sender
                print"Date: %s"%date
                print"Message: %s"%decrypted_text
                print""

                conn = sqlite3.connect('local.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO messages (message,sender,receipient,date) VALUES (?,?,?,?)',(decrypted_text,sender,receipient,date))
                conn.commit()
                conn.close()
                

            elif json_data["type"] == "file":

                #Handles receiving of a file, after receiving a filename
                sender = json_data["sender"]
                shared_key = self._encryption_engine.fetch_local_shared_key(sender) 
                filename = self._encryption_engine.decrypt_text(json_data["message"],shared_key)

                print "Receiving %s from %s, please wait...."%(filename,sender)
                
                #Prevent recv from taking too long
                self.client_socket.settimeout(5)

                try:
                    with open(filename,"wb") as f:
                        chunk = self.client_socket.recv(1024)
                        data = ''
                        if chunk == "/0end":
                            pass
                        else:
                            while chunk:
                                if chunk[-5:] == '/0end':
                                    data+=chunk[:-5]
                                    break
                                data+=chunk
                                chunk = self.client_socket.recv(1024)

                            decrypted_data = self._encryption_engine.decrypt_file(data,shared_key)
                            f.write(decrypted_data)
                except:
                    pass

                self.client_socket.settimeout(None)

                print "File Received"
                        
            elif json_data["type"] == "unread":

                unread_messages = json_data["objects"]
                for message in unread_messages:
                    
                    sender = message["sender"]
                    date = message["date"]
                    message_text = message["message"]
                    receipient = message["receipient"]
                    shared_key = self._encryption_engine.fetch_local_shared_key(sender)
                    decrypted_text = self._encryption_engine.decrypt_text(message_text,shared_key)
                    
                    print""
                    print"From: %s"%sender
                    print"Date: %s"%date
                    print"Message: %s"%decrypted_text
                    print""

                    conn = sqlite3.connect('local.db')
                    cursor = conn.cursor()
                    cursor.execute('INSERT INTO messages (message,sender,receipient,date) VALUES (?,?,?,?)',(decrypted_text,sender,receipient,date))
                    conn.commit()
                    conn.close()
                
            
            elif json_data["type"] == "alert":
                
                #Handles alerts like success and fails
                
                message = json_data["message"]
                
                #This helps throw an exception if encryption is tried
                #on a non existent key
                if json_data["success"] == False:
                    self._remote_user_key = 0
                    
                print""
                print"Alert: %s"%message
                print""


            elif json_data["type"] == "publickey":
                #Handles response when you fetch a public key remotely
                
                username = json_data["username"]
                public_key = json_data["public_key"]
                
                print""
                print"Public Key for %s: %s"%(username,public_key)
                print""
                
                self._remote_user_key = public_key

            elif json_data["type"] == "sharedkey":

                #Handle when a user sends you a shared key
                #Receives key and saves it to the database
                
                message = json_data["message"]
                sender = json_data["sender"]
                
                private_key = self._encryption_engine.fetch_private_key()
                decrypted_shared_key = self._encryption_engine.decrypt_key(message,private_key)
                self._encryption_engine.save_shared_key(sender,decrypted_shared_key)
                
                print""             


            self._user_option_menu_header()
            
        except:
            if response == 'sent':
                print""
                print"Success"
                print""
            else:
                print""
                print"Failed"
                print""
            raise
            
            self._user_option_menu_header()

    def _user_option_menu_header(self):
        print ""
        print "1. Send Message "
        print "2. View Conversation "
        print "3. View Inbox "
        print "4. View Outbox "
        print "5. View Unread "
        print "6. Exit "
        print ""
        print "> ",
        
    def _user_option_menu(self):
        
        self._user_option_menu_header()

        while True:

            menu_option = raw_input("")

            if menu_option == "1":
                
                self._send_message_method()
                
            elif menu_option == "2":
                
                self._view_conversation_method()
                
            elif menu_option == "3":
                
                self._view_inbox_method()
                
            elif menu_option == "4":
                
                self._view_outbox_method()

            elif menu_option == "5":

                self._view_unread_method()

            elif menu_option == "6":
                sys.exit(0)

    def _fetch_remote_public_key(self,user):
        json_request = '{"username":"%s","logged_user":"%s","api_key":"%s","type":"publickey"}'%(user,self._logged_user,self._logged_user_api_key)
        self.client_socket.sendall(json_request)
        self.client_socket.send("/0")

        timeout = 5
        count = 0

        while self._remote_user_key is None:
            #Check every second if the remote key was fetched
            time.sleep(1)
            #If server responds with code 0 (from the receiving thread) set key to None
            #The try catch will throw an exception an fail gracefully
            if self._remote_user_key == 0:
                self._remote_user_key = None
                break

        remote_key = self._remote_user_key
        self._remote_user_key = None
        
        return remote_key

    def _send_message_method(self):

        IS_FILE = False
        
        print ""
        message = raw_input("Enter message: ")
        receipient = raw_input("Enter recipient: ")
        print ""

        if message[:6] == "file: ":
            IS_FILE = True
            message_list = message.split("file: ")
            message = message_list[1]
            filename = message

            

        sender = self._logged_user
        shared_key = self._encryption_engine.fetch_local_shared_key(receipient)

        try:
            if shared_key is not None:
                #The user has a shared key stored for recipient, so head straight to encryption
                encrypted_text = self._encryption_engine.encrypt_text(message,shared_key)
                
            else:
                #The user has no shared key stored for the recipient, 
                #so generate and send them a shared key
                
                #fetch remote public key
                
                public_key = self._fetch_remote_public_key(receipient)
                #print "Public key fetched"
                
                #generate shared key
                
                shared_key = self._encryption_engine.generate_shared_key()
                #print "Shared key generated"
                
                #encrypt shared key with public key
                
                encrypted_shared_key = self._encryption_engine.encrypt_key(shared_key,public_key)
                #print"Shared key encrypted"
                #save shared key and username to database

                self._encryption_engine.save_shared_key(receipient,shared_key)
                #print "Shared key saved"
                #send to receipient

                request_json = '{"sender":"%s","receipient":"%s","logged_user":"%s","message":"%s","api_key":"%s","type":"sharedkey"}'%(sender,receipient,sender,encrypted_shared_key,self._logged_user_api_key)
                self.client_socket.sendall(request_json)
                self.client_socket.send("/0")

                #This wait is just so the recipient of the message can do all necessary calculations and store the key
                time.sleep(5)
                encrypted_text = self._encryption_engine.encrypt_text(message,shared_key)

            #Finally send the (encrypted) message

            if IS_FILE == False:                
                message_json = '{"message":"%s", "receipient":"%s", "sender":"%s", "logged_user":"%s", "api_key":"%s","type":"message"}'%(encrypted_text,receipient,sender,self._logged_user,self._logged_user_api_key)
                self.client_socket.sendall(message_json)
                self.client_socket.send("/0")
                

                current_time_epoch = time.time()
                time_format = '%Y/%m/%d %H:%M:%S'
                date = time.strftime(time_format,time.localtime(current_time_epoch))
            
                conn = sqlite3.connect('local.db')
                cursor = conn.cursor()
                cursor.execute('INSERT INTO messages (message,sender,receipient,date) VALUES (?,?,?,?)',(message,sender,receipient,date))
                conn.commit()
                conn.close()
                
            else:

                try:

                    with open(filename,"rb") as f:
                        
                        print "Sending file to %s...."%receipient
                        message_json = '{"message":"%s", "receipient":"%s", "sender":"%s", "logged_user":"%s", "api_key":"%s","type":"file"}'%(encrypted_text,receipient,sender,self._logged_user,self._logged_user_api_key)
                        self.client_socket.sendall(message_json)
                        self.client_socket.send("/0")
                        
                        data = f.read()
                        encrypted_data = self._encryption_engine.encrypt_file(data,shared_key)
                        self.client_socket.sendall(encrypted_data+"/0end")

                    print "Done!"    
                except:
                    print "There was an error... Check that file exists"
                    self._user_option_menu_header()
                    pass
                

            
        except:
            #"There was an error!"
            pass    

    def _view_conversation_method(self):
        
        print ""
        user1 = raw_input("View conversation with: ")
        print""
        user2 = self._logged_user

        conn = sqlite3.connect("local.db")
        cursor = conn.cursor()

        conversation_sql = 'SELECT message,sender,receipient,date FROM messages WHERE (sender=? AND receipient=?) OR (sender=? AND receipient=?)'
        messages = cursor.execute(conversation_sql,(user1,user2,user2,user1))

        for message in messages:
            print""
            print"From: %s"%message[1]
            print"To: %s"%message[2]
            print"Date: %s"%message[3]
            print"Message: %s"%message[0]
            print""

        self._user_option_menu_header()
            

    def _view_inbox_method(self):
        conn = sqlite3.connect("local.db")
        cursor = conn.cursor()
        
        receipient = self._logged_user
        
        view_received_messages_sql = 'SELECT message,sender,receipient,date FROM messages WHERE receipient=?'
        messages = cursor.execute(view_received_messages_sql,(receipient,))

        for message in messages:
            print""
            print"From: %s"%message[1]
            print"Date: %s"%message[3]
            print"Message: %s"%message[0]
            print""

        conn.close()

        self._user_option_menu_header()

    def _view_unread_method(self):
        
        request = '{"logged_user":"%s","api_key":"%s","type":"unread"}'%(self._logged_user,self._logged_user_api_key)
        self.client_socket.sendall(request)
        self.client_socket.send("/0")

    
    def _view_outbox_method(self):
        conn = sqlite3.connect("local.db")
        cursor = conn.cursor()
        
        sender = self._logged_user
        
        view_received_messages_sql = 'SELECT message,sender,receipient,date FROM messages WHERE sender=?'
        messages = cursor.execute(view_received_messages_sql,(sender,))
        
        for message in messages:
            print""
            print"To: %s"%message[2]
            print"Date: %s"%message[3]
            print"Message: %s"%message[0]
            print""
        conn.close()
        self._user_option_menu_header()
                
            
if __name__=="__main__":
    HOST = '127.0.0.1'
    PORT = 1000
    client = Client(HOST,PORT)
        

    
