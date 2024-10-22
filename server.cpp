#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <vector>
#include <filesystem>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

#define PORT 4444
#define MAX_CLIENTS 20

namespace fs = std::filesystem;

std::string server_music_dir = "./server_files/";
std::string client_log_dir = "./server_files/client_logs/";

std::string get_current_timestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream timestamp;
    timestamp << std::put_time(std::localtime(&now_time), "%Y-%m-%d %H:%M:%S");
    return timestamp.str();
}

std::string compute_file_hash(const std::string& file_path) {
    std::ifstream file(file_path, std::ifstream::binary);
    if (!file) {
        throw std::runtime_error("File not found: " + file_path);
    }

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD* md = EVP_sha256();
    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize digest");
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        if (1 != EVP_DigestUpdate(mdctx, buffer, file.gcount())) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error("Failed to update digest");
        }
    }

    if (1 != EVP_DigestUpdate(mdctx, buffer, file.gcount())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update digest");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize digest");
    }

    EVP_MD_CTX_free(mdctx);

    std::ostringstream result;
    for (unsigned int i = 0; i < hash_len; ++i) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return result.str();
}

std::string handle_list() {
    std::string file_list;
    bool has_files = false;

    for (const auto &entry : fs::directory_iterator(server_music_dir)) {
        if (!fs::is_regular_file(entry.path())) {
            continue;
        }
        has_files = true;  // Mark that we found at least one file
        std::string file_name = entry.path().filename().string();
        std::string file_hash = compute_file_hash(entry.path().string());
        file_list += file_name + "|" + file_hash + "\n";  // Send name|hash to client
    }

    if (!has_files) {
    // Handle the case where there are no regular files (e.g., log a message, return empty string)
    return "empty"; // or handle the case appropriately
    }

    return file_list;
}

class ServerConnection {
public:
    // Constructor
    ServerConnection(int port) {
        if (!fs::exists(client_log_dir)) {
            std::cout << "Directory " << client_log_dir << " does not exist. Creating..." << std::endl;
            fs::create_directories(client_log_dir);
        }

        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            throw std::runtime_error("Socket failed");
        }

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }
    }

    // Start listening 
    void startListening(int max_clients) {
        if (listen(server_fd, max_clients) < 0) {
            throw std::runtime_error("Listen failed");
        }
        std::cout << "Server listening on port " << PORT << std::endl;
    }

    // Accepting client connection
    int acceptConnection() {
        int addrlen = sizeof(address);
        int new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) {
            throw std::runtime_error("Accept failed");
        }
        std::cout << "New connection from " << inet_ntoa(address.sin_addr) << ":" << ntohs(address.sin_port) << std::endl;
        return new_socket;
    }

    ~ServerConnection() {
        close(server_fd);
    }

private:
    int server_fd;
    struct sockaddr_in address;
};

// Handle client commands
void* handle_client(void* client_socket_ptr);

int main() {
    try {
        ServerConnection server(PORT);
        server.startListening(MAX_CLIENTS);

        pthread_t thread_id;
        while (true) {
            int new_socket = server.acceptConnection();

            //new thread for each client with pthread
            int* client_socket_ptr = new int(new_socket);
            if (pthread_create(&thread_id, NULL, handle_client, (void*)client_socket_ptr) != 0) {
                perror("Thread creation failed");
                delete client_socket_ptr;
                continue;
            }

            //detach to handle client independently
            pthread_detach(thread_id);
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}

void* handle_client(void* client_socket_ptr) {
    int client_socket = *(int*)client_socket_ptr;
    delete (int*)client_socket_ptr;

    char buffer[1024] = {0};

    //get token from client
    int valread = read(client_socket, buffer, 1024);
    if (valread <= 0) {
        std::cout << "Client disconnected before sending token." << std::endl;
        close(client_socket);
        pthread_exit(NULL);
    }
    std::string client_token(buffer, 6); 
    std::cout << "Client with token: " << client_token << " connected." << std::endl;

    //create log file
    std::string log_file_path = client_log_dir + "client_" + client_token + ".txt";
    if (!fs::exists(log_file_path)) {
        std::ofstream log_file(log_file_path);
        log_file << "[" << get_current_timestamp() << "] " << "Client log created for token: " << client_token << std::endl;
        log_file.close();
    }

    //welcome
    std::string welcome_msg = "Welcome to the server, client " + client_token + "!\n";
    send(client_socket, welcome_msg.c_str(), welcome_msg.size(), 0);
    std::ofstream log_file(log_file_path, std::ios_base::app);
    log_file << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] logged in." << std::endl;
    log_file.close();

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        valread = read(client_socket, buffer, 1024);
        if (valread <= 0) {
            std::ofstream log_file(log_file_path, std::ios_base::app);
            log_file << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] disconnected." << std::endl;
            log_file.close();
            std::cout << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] disconnected." << std::endl;
            close(client_socket);
            pthread_exit(NULL);
        }

        std::string command(buffer);
        std::cout << "Received from client [" << client_token << "]: " << command << std::endl;

        if (strcmp(buffer, "LIST") == 0 || strcmp(buffer, "DIFF") == 0) {
            std::string files = handle_list();
            std::cout << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] requested " << command << " command." << std::endl;
            std::cout << "Files on server: \n" + files;

            memset(buffer, 0, sizeof(buffer));
            send(client_socket, files.c_str(), files.size(), 0);
            
            std::ofstream log_file(log_file_path, std::ios_base::app);
            log_file << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] requested " << command << " command." << std::endl;
            log_file.close();
        } else if (strcmp(buffer, "PULL") == 0) {
            std::string files = handle_list();
            std::cout << "Files on server: \n" + files;
            memset(buffer, 0, sizeof(buffer));
            send(client_socket, files.c_str(), files.size(), 0);

            memset(buffer, 0, sizeof(buffer));
            valread = read(client_socket, buffer, 1024);
            if (valread <= 0 || strlen(buffer) == 0) {
                break;
            }
            int num_of_file = atoi(buffer);
            std::cout << num_of_file << "files need to be downloaded." << std::endl;

            for (int i = 0; i < num_of_file; i++) {
                // Receive the file name from the client
                memset(buffer, 0, sizeof(buffer));
                valread = read(client_socket, buffer, 1024);
                if (valread <= 0 || strlen(buffer) == 0) {
                    break;
                }
                std::string requested_file(buffer);
                std::cout << "Sending requested filenamed " << buffer << "..."<< std::endl;
                std::string file_path = server_music_dir + requested_file;

                // Open the file and send the size to the client
                std::ifstream file(file_path, std::ios::binary | std::ios::ate);
                size_t file_size = file.tellg();
                std::string file_size_str = std::to_string(file_size);
                send(client_socket, file_size_str.c_str(), file_size_str.size(), 0);

                file.seekg(0, std::ios::beg);

                // Send the file in chunks
                size_t bytes_sent = 0;
                char file_buffer[1024];
                while (bytes_sent < file_size) {
                    file.read(file_buffer, sizeof(file_buffer));
                    size_t bytes_to_send = file.gcount();
                    if (bytes_to_send <= 0) {
                        break;
                    }
                    send(client_socket, file_buffer, bytes_to_send, 0);
                    bytes_sent += bytes_to_send;
                }

                file.close();
                std::cout << "File sent: " << requested_file << " (" << bytes_sent << " bytes)" << std::endl;

                // Logging
                std::ofstream log_file(log_file_path, std::ios_base::app);
                log_file << "[" << get_current_timestamp() << "] "
                         << "Client [" << client_token << "] downloaded file: " << requested_file << std::endl;
                log_file.close();
            }


        } else if (strcmp(buffer, "LEAVE") == 0) {
            std::cout << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] disconnected." << std::endl;
            std::ofstream log_file(log_file_path, std::ios_base::app);
            log_file << "[" << get_current_timestamp() << "] " << "Client [" << client_token << "] attempted and disconnected." << std::endl;
            log_file.close();
            close(client_socket);
            pthread_exit(NULL);
        } else {
            std::cout << "Unknown command from client [" << client_token << "]: " << command << std::endl;
        }
    }
    return NULL;
}