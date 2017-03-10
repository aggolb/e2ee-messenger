'''
## MESSAGE SERVER 1.0
##
## The simple messaging server can be installed on any machine
## It's main function is to receive, route and send messages to users
## It also allows users to create accounts, complete with password authentication
## Finally, it stores the public keys used for End to End encryption.
## Uses a json api to perform actions
## Logged messages are indecipherable to all except the communicating parties
##
## Author: Shimpano Mutangama
'''

import socket
import select
import threading
import time
import json
import sqlite3
import hashlib

class Message:

    def __init__(self,message,sender,receipient):
        self.message = message
        self.sender = sender
        self.receipient = receipient
        self.time = time.time()
        

    def time_str(self):
        current_time_epoch = self.time
        time_format = '%Y/%m/%d %H:%M:%S'
        return time.strftime(time_format,time.localtime(current_time_epoch))

    def json(self):
        json_string = '{"message":"%s", "sender":"%s", "receipient":"%s", "date":"%s","success":true,"type":"message"}'%(self.message,self.sender,self.receipient,self.time_str())
        return json_string
    
class MessageServer:

    def __init__(self):
        self._connections = {}
        self.INPUTS = []
        self.OUTPUTS = []
        self._message_queues = {}
        self._message_queue = []
        self.server_socket = None      
  

    def _init_database(self):
        #Create database and tables
        self._conn = sqlite3.connect('message_server.db')
        self._cursor = self._conn.cursor()
        self._cursor.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY NOT NULL, message varchar(200), sender varchar(200), receipient varchar(200), date varchar(200), read INTEGER)")
        self._cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY NOT NULL, username varchar(200),password varchar(200),api_key varchar(200),public_rsa varchar(2000))")
        self._conn.commit()
        self._conn.close()
        
    def start(self):
        
        self._init_database()

        t = threading.Thread(target = self.listen_for_connections)
        t.daemon = True
        t.start()

        time.sleep(5)

        while True:
            choice = raw_input(">>")
            if len(choice) > 0:
                
                print "Shutdown..."
                
                for connection in self._connections:
                    self._connections[connection].shutdown(0)
                    self._connections[connection].close()
                break

                
    
    def listen_for_connections(self):
        SERVER_HOST = '0.0.0.0'
        SERVER_PORT = 1000
        SERVER_TUPLE = (SERVER_HOST,SERVER_PORT)
        
        self.server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server_socket.bind(SERVER_TUPLE)
        self.server_socket.listen(5)
        #self.server_socket.settimeout(5)

        self._connections['server_socket'] = self.server_socket
        self.INPUTS.append(self.server_socket)
        ERROR_SOCKETS = []
        
        while True:
            print "Listening for connections...\n"
            read_sockets,write_sockets,error_sockets = select.select(self.INPUTS,[],[])

            for sock in read_sockets:
                if sock == self.server_socket:
                    client_connection,client_address = self.server_socket.accept()

                    print "Connected: ",client_address
                    data = client_connection.recv(1024)
                    response = self.parse_data(data)
                    client_connection.sendall(response)
                    json_response = json.loads(response)
                    
                    if json_response["success"] == True:
                        client_id = json_response["username"]
                        self._connections[client_id] = client_connection
                        #client_connection.setblocking(0)
                        self.INPUTS.append(client_connection)
                        print "%s connected"%(client_id)
                    else:
                        print"Login or Registration Failed"
                else:
                    try:
                        self.receive_messages(sock)
                        #self.INPUTS.remove(sock)
                    except:
                        #raise
                        error_sockets.append(sock)
                        print"Added an error socket"

            for sock in error_sockets:
                sock.close()
                self.INPUTS.remove(sock)


    def parse_data(self,data):
        print "Request: %s"%data
        json_data = json.loads(data)
        #print"JSON received: %s"%json_data
        if json_data["type"] == "registration":
            response = self.register_user(json_data)
        elif json_data["type"] == "login":
            response = self.login_user(json_data)
        return response

    def check_user_api_key(self, username, key):
        conn = sqlite3.connect("message_server.db")
        cursor = conn.cursor()

        check_key_sql = 'SELECT * FROM users WHERE username=? AND api_key=?'
        records = cursor.execute(check_key_sql,(username,key))
        count = 0
        
        for record in records:
            count+=1

        conn.close()

        if count == 0:
            return False
        else:
            return True
            
        

    def register_user(self,json_data):
        conn = sqlite3.connect("message_server.db")
        cursor = conn.cursor()
        
        username = json_data["username"]
        password = json_data["password"]
        password_hash = hashlib.sha256(password).hexdigest()
        public_rsa = json_data["public_key"]
        user_kvp = "%s:%s"%(username,password)
        api_key = "AK"+hashlib.md5(user_kvp).hexdigest()[::-1]

        check_user_exists_sql = 'SELECT * FROM users WHERE username=?'
        records = cursor.execute(check_user_exists_sql,(username,))
        count = 0
        
        for user in records:        
            count+=1        
        if count > 0:         
            response_json = '{"success":false,"reason":"username already registered."}'
        else:
            registration_sql = 'INSERT INTO users (username,password,api_key,public_rsa) VALUES (?,?,?,?)'
            try:
                cursor.execute(registration_sql,(username,password_hash,api_key,public_rsa))
                response_json = '{"username":"%s","api_key":"%s","success":true}'%(username,api_key)
            except:
                response_json = '{"success":false,"reason":"failed."}'
                
        conn.commit()
        conn.close()

        return response_json

    def login_user(self,json_data):
        conn = sqlite3.connect("message_server.db")
        cursor = conn.cursor()

        username = json_data["username"]
        password = json_data["password"]
        password_hash = hashlib.sha256(password).hexdigest()

        login_sql = 'SELECT username,api_key FROM users WHERE username=? AND password=?'
        user = cursor.execute(login_sql,(username,password_hash)).fetchone()

        print"User Object: ",user

        if user is not None:
            response_json = '{"username":"%s","api_key":"%s","success":true}'%(user[0],user[1])
        else:
            response_json = '{"success":false,"reason":"incorrect login details."}'

        conn.close()
            
        return response_json
        

    def receive_messages(self,client_socket):
        while True:

            try:
                chunk= client_socket.recv(1024)
                #print"First chunk received"
                data = ''
                while chunk:
                    if chunk[-2:] == "/0":
                        data+=chunk[:-2]
                        break
                    data+=chunk
                    chunk = client_socket.recv(1024)

                #print"Request Received"
                print"Received: ",data

                request = json.loads(data)

                logged_user = request["logged_user"]
                api_key = request["api_key"]

                #Check if user is using the right api key
                authorized = self.check_user_api_key(logged_user,api_key)
                
                if authorized:
                
                    if request["type"] == "message":
                        
                        message = self.parse_message_data(data)
                        self.send_message(message)

                    elif request["type"] == "file":
                        
                        try:
                            
                            receipient = request["receipient"]
                            receipient_socket = self._connections[receipient]
                            receipient_socket.sendall(json.dumps(request)+"/0")

                            chunk = client_socket.recv(1024)
                            while chunk:
                                if chunk[-5:] == "/0end":
                                    receipient_socket.send(chunk)
                                    break
                                receipient_socket.send(chunk)
                                chunk = client_socket.recv(1024)
                                

                            client_socket.sendall('{"message":"File Successfully Sent","type":"alert","success":true}')
                            client_socket.send("/0")    
                 
                        except:
                            raise
                            response = '{"message":"Failed to Send","type":"alert","success":false}'
                            client_socket = self._connections[request["logged_user"]]    
                            client_socket.sendall(response)
                            client_socket.send("/0")

                        client_socket.settimeout(None)
                        
                    elif request["type"] == "unread":
                        logged_user = request["logged_user"]
                        response = self.fetch_unread_messages(logged_user)
                        self.read_messages(logged_user)
                        json_response = json.dumps(response)
                        
                        if response == 'fail':
                            json_response = '{"message":"Failed to Send","type":"alert","success":false}'

                        client_socket = self._connections[request["logged_user"]]
                        client_socket.sendall(json_response)
                        client_socket.send("/0")
                        
                        
                    elif request["type"] == "publickey":
                        response = self.fetch_public_key(request["username"])
                        
                        if response == 'fail':
                            response = '{"message":"Failed to Send","type":"alert","success":false}'
                        
                        client_socket = self._connections[request["logged_user"]]
                        #print"Key Response: %s"%response
                        client_socket.sendall(response)
                        client_socket.send("/0")

                    elif request["type"] == "sharedkey":
                        try:
                            
                            receipient_socket = self._connections[request["receipient"]]
                            receipient_socket.sendall(json.dumps(request))
                            receipient_socket.send("/0")
                            
                        except:
                            
                            response = '{"message":"Failed to Send","type":"alert","success":false}'
                            client_socket = self._connections[request["logged_user"]]    
                            client_socket.sendall(response)
                            client_socket.send("/0")
                                    
                else:
                    
                    response = '{"message":"Failed to Send... You are not authorized.","type":"alert","success":false}'
                    self.client_socket.sendall(response)
                    self.client_socket.send("/0")
                    
            
            except:
                raise

            break
        
    def parse_message_data(self,data):
        #print "Data Received: %s"%data
        message_data = json.loads(data)
        
        message_text = message_data["message"]
        sender = message_data["sender"]
        receipient = message_data["receipient"]
        
        message = Message(message_text,sender,receipient)

        return message

    def user_exists(self,username):

        conn = sqlite3.connect("message_server.db")
        cursor = conn.cursor()
        user_exists_sql = 'SELECT * FROM users WHERE username=?'
        records = cursor.execute(user_exists_sql,(username,))
        count = 0
        for record in records:
            count+=1

        conn.close()
        
        if count == 0:
            return False
        else:
            return True
        
        
    def send_message(self,message):

        try:
            if self.user_exists(message.receipient):
                self.save_message(message)
            receipient_socket = self._connections[message.receipient]
            sender_socket = self._connections[message.sender]
            receipient_socket.sendall(message.json())
            receipient_socket.send("/0")
            sender_socket.sendall('{"message":"Message Successfully Sent","type":"alert","success":true}')
            sender_socket.send("/0")
            self.read_messages(message.receipient)
        except:
            #raise
            sender_socket = self._connections[message.sender]
            if self.user_exists(message.receipient):
                sender_socket.sendall('{"message":"Message Successfully Sent","type":"alert","success":true}')
            else:
                sender_socket.sendall('{"message":"Failed to Send","type":"alert","success":false}')
            sender_socket.send("/0")   

    def save_message(self,message):
        try:
            conn = sqlite3.connect('message_server.db')
            cursor = conn.cursor()
            read = 0 #False
            save_message_sql = 'INSERT INTO messages (message,sender,receipient,date,read) VALUES (?,?,?,?,?)'
            cursor.execute(save_message_sql,(message.message,message.sender,message.receipient,message.time_str(),read))
            conn.commit()
            conn.close()
        except:
            raise

    def read_messages(self,username):

        try:
            conn = sqlite3.connect('message_server.db')
            cursor = conn.cursor()
            read_sql = 'UPDATE messages SET read=1 WHERE receipient=? AND read=0'
            cursor.execute(read_sql,(username,))
            conn.commit()
            conn.close()
        except:
            print "Something in the SQL"
            raise
       
    
    def fetch_unread_messages(self,username):
        try:
            conn = sqlite3.connect('message_server.db')
            cursor = conn.cursor()
            fetch_unread_sql = 'SELECT message,sender,receipient,date FROM messages WHERE receipient=? AND read=0'
            unread_messages = cursor.execute(fetch_unread_sql,(username,))
            
            
            objects = []
            for message in unread_messages:
                message_dict = {}
                message_dict['message'] = message[0]
                message_dict['sender'] = message[1]
                message_dict['receipient'] = message[2]
                message_dict['date'] = message[3]
                objects.append(message_dict)

            conn.close()

            response = {}
            response['count'] = len(objects)
            response['objects'] = objects
            response['receipient'] = username
            response['success'] = True
            response["type"] = "unread"
        except:
            raise
            response == "fail"

        return response

    #Public Key
    def fetch_public_key(self,username):
        try:
            conn = sqlite3.connect("message_server.db")
            cursor = conn.cursor()
            public_key_sql = 'SELECT username,public_rsa FROM users WHERE username=?'
            records = cursor.execute(public_key_sql,(username,))
            key_record = records.fetchone()
            if key_record is not None:
                json_response = '{"username":"%s","public_key":"%s","type":"publickey"}'%(key_record[0],key_record[1].replace("\n","\\n"))
            else:
                json_response = 'fail'
                
            conn.commit()
            conn.close()

            return json_response
            
        except:
            return "fail"
            

def main():
    global server
    server = MessageServer()
    server.start()

if __name__=="__main__":
    main()
