Client Server communication network with built in packet loss/drop recovery.

To test the network, install packet errors and packet drops using must program. The must program is built by Mike Katchabaw. Please reference must_README.txt for instructions.

Steps to run application

1. run the server file
2. copy the port number that the server is running on
3. run the client file with arguments
	arguments -> user chat://host:portNumber
	swap out user with a name and portNumber with the port number return by the server file
4. complie and run must.c to install errors


Please note that the network is cable of sending files. To send files type !attach {filename} into the client to send the file to the server.
