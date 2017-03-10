# e2ee-messenger
A simple "End to End Encryption" messaging app with user accounts and file sharing, it's built for LAN but can easily be used over the internet as well.

#Prepare
- Download and install pycrypto

#How to use
- Choose any computer to be the server (make sure you know it's host name (usually IP address) and change PORT if necessary)
- Copy and run m_server.py 
- Copy the "client" folder containing m_client.py and encryption_engine.py to a folder on the client computer.
- Open m_client.py and change the server host name and port to match the computer with m_server.py
- Run m_client.py
- Follow on screen instructions
