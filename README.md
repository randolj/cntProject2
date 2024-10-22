# Project 2 Application - CNT4007

This application is designed for Project 2 of CNT4007. It implements a client-server system that synchronizes files between a central server and multiple clients using TCP/IP communication. This README file provides instructions on how to set up and use the application.

## How to Use

### 1. Setting Up
- **Server IP Address:** The default IP address of the server is `127.0.0.1`. If you are placing the server on any IP address other than this, please change the `SERVER_IP` variable in `client.cpp` to reflect the actual IP address.
- **Compilation:** Compile both the client and server applications from their respective source files using `make`.
- **Executable Placement:** Place the server executable in one folder and the client executable in a separate folder. For multiple clients, copy the client executable to a new folder for each client.

### 2. Running the Server
- **Initialization:** Start the server, and a sub-directory named `server_files` will be created by the executable.
- **Server Database:** Put any file under the `server_files` folder to use as the server database.
- **Execution:** Start the server by running the server executable like `./server_P2`.
- **Configuration:** You can adjust the port number and maximum concurrent users (default: Port 4444 and 20 max users) by modifying the corresponding variables in the server's and client’s `.cpp` files and recompiling.

### 3. Running the Client
- **Starting the Client:** Start the client by running the client executable like `./client_P2`.
- **Interface:** Once started, the client provides a simple command-line interface to interact with the server.

### 4. Client Commands
- **LIST:** Lists all files available on the server.
- **DIFF:** Compares files between the client and the server, identifying files missing on the client side (based on file hashes).
- **PULL:** Downloads files from the server that are missing on the client. If a file with the same name but different contents already exists, the new file will be saved with a modified name (e.g., `file_name (1).txt`).
- **LEAVE:** Ends the session and disconnects from the server.

### 5. Log Infos
- **Logging:** The server will keep the log infos of each client under `./server_files/client_logs`.
