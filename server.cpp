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

#define PORT 4321
#define MAX_CLIENTS 10

namespace fs = std::filesystem;

std::string server_music_dir = "./server_files/";

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
    for (const auto &entry : fs::directory_iterator(server_music_dir)) {
        std::string file_name = entry.path().filename().string();
        std::string file_hash = compute_file_hash(entry.path().string());
        file_list += file_name + "|" + file_hash + "\n";  // Send name|hash to client
    }
    return file_list;
}

class ServerConnection {
public:
    ServerConnection(int port) {
        // Create socket file descriptor
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            throw std::runtime_error("Socket failed");
        }

        // Bind socket to the port
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Bind failed");
        }
    }

    void startListening(int max_clients) {
        if (listen(server_fd, max_clients) < 0) {
            throw std::runtime_error("Listen failed");
        }
        std::cout << "Server listening on port " << PORT << std::endl;
    }

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

void* handle_client(void* client_socket_ptr);

int main() {
    try {
        ServerConnection server(PORT);
        server.startListening(MAX_CLIENTS);

        pthread_t thread_id;
        while (true) {
            int new_socket = server.acceptConnection();

            // Create a new thread for each client
            int* client_socket_ptr = new int(new_socket);
            if (pthread_create(&thread_id, NULL, handle_client, (void*)client_socket_ptr) != 0) {
                perror("Thread creation failed");
                delete client_socket_ptr;
                continue;
            }

            // Detach thread to handle client independently
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
    std::string welcome_msg = "Welcome to the server!\n";
    send(client_socket, welcome_msg.c_str(), welcome_msg.size(), 0);

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int valread = read(client_socket, buffer, 1024);
        if (valread <= 0) {
            std::cout << "Client disconnected." << std::endl;
            close(client_socket);
            pthread_exit(NULL);
        }

        std::cout << "Received: " << buffer << std::endl;

        if (strcmp(buffer, "LIST") == 0 || strcmp(buffer, "DIFF") == 0) {
            std::string files = handle_list();
            std::cout << files;

            memset(buffer, 0, sizeof(buffer));
            send(client_socket, files.c_str(), files.size(), 0);
        }

    }
}
