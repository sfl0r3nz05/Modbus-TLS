# pymodbus-tls

pymodbus-tls is a project based on pymodbus library which uses sslsocket to create a socket TLS to ensure the communication

How to use the project:
1. Install pymodbus lybrary (pip install pymodbus)
2. Clone the repository
3. Change the server/client of pymodbus
	* sudo cp -r ~/pymodbus-tls/pymodbus/server/sync.py ~/.local/lib/python2.7/site-packages/pymodbus/server/sync.py
	* sudo cp -r ~/pymodbus-tls/pymodbus/client/sync.py ~/.local/lib/python2.7/site-packages/pymodbus/client/sync.py
4. cd ~/pymodbus-tls/example
5. Remove Role.db, ./conf-, servercert.pem, serverkey.pem, servercert.srl
6. Launch the server: sudo python synchronous_server.py
7. Launch the client: sudo python synchronous_client.py
