#include <iostream>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <openssl/evp.h>
#include <fstream>
#include <sstream>

#define PORT 4321
#define SERVER_IP "127.0.0.1"

namespace fs = std::filesystem;
std::string client_music_dir = "./client_files/";


class ClientConnection {
public:
    ClientConnection(const std::string& ip, int port) {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid address/ Address not supported");
        }

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            throw std::runtime_error("Socket creation error");
        }
    }

    void connectToServer() {
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            throw std::runtime_error("Connection failed");
        }
        std::cout << "Connected to the server" << std::endl;
        std::string response = receiveMessage();
        if (!response.empty()) {
            std::cout << response << std::endl;
        }
    }

    void sendMessage(const std::string& message) {
        send(sock, message.c_str(), message.size(), 0);
    }

    std::string receiveMessage() {
        char buffer[1024] = {0};
        int valread = read(sock, buffer, 1024);
        if (valread > 0) {
            buffer[valread] = '\0';
            return std::string(buffer);
        }
        return "";
    }

    ~ClientConnection() {
        close(sock);
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

    void handleListFiles() {
        // Send LIST command and handle response
        sendMessage("LIST");
        std::string response = receiveMessage();
        if (!response.empty()) {
            std::cout << "Server File List: " << std::endl;
            // Split the response by lines (each line is "file_name|file_hash")
            size_t pos = 0;
            std::string line;
            while ((pos = response.find("\n")) != std::string::npos) {
                line = response.substr(0, pos);

                // Extract the file name part before the '|'
                size_t delimiter_pos = line.find("|");
                if (delimiter_pos != std::string::npos) {
                    std::string file_name = line.substr(0, delimiter_pos);  // Keep file name
                    std::cout << file_name << std::endl;
                }
                response.erase(0, pos + 1);
            }
        }
    }

    void handleDiff() {
        // Send DIFF command and handle response
        sendMessage("DIFF");
        std::string server_file_list = receiveMessage();

        // Get client files and hashes
        std::vector<std::pair<std::string, std::string>> client_files;
        for (const auto &entry : fs::directory_iterator(client_music_dir)) {
            std::string file_name = entry.path().filename().string();
            std::string file_hash = compute_file_hash(entry.path().string());
            client_files.push_back({file_name, file_hash});
        }

        // Parse the server file list (format: file_name|file_hash)
        std::vector<std::pair<std::string, std::string>> server_files;
        size_t pos = 0;
        std::string token;
        while ((pos = server_file_list.find("\n")) != std::string::npos) {
            token = server_file_list.substr(0, pos);
            size_t delimiter_pos = token.find("|");
            std::string file_name = token.substr(0, delimiter_pos);
            std::string file_hash = token.substr(delimiter_pos + 1);

            server_files.push_back({file_name, file_hash});
            server_file_list.erase(0, pos + 1);
        }

        // Find files that are in the server but not in the client (by hash comparison)
        std::vector<std::string> missing_in_client;
        for (const auto& server_file : server_files) {
            auto it = std::find_if(client_files.begin(), client_files.end(), [&](const auto& client_file) {
                return client_file.second == server_file.second;  // Compare hashes
            });
            if (it == client_files.end()) {
                missing_in_client.push_back(server_file.first);  // File is missing in client
            }
        }

        std::cout << "Files missing in client: \n";
        for (const auto &file : missing_in_client) {
            std::cout << file << "\n";
        }

        // Find files that are in the client but not in the server (by hash comparison)
        std::vector<std::string> missing_in_server;
        for (const auto& client_file : client_files) {
            auto it = std::find_if(server_files.begin(), server_files.end(), [&](const auto& server_file) {
                return server_file.second == client_file.second;  // Compare hashes
            });
            if (it == server_files.end()) {
                missing_in_server.push_back(client_file.first);  // File is missing in server
            }
        }

        std::cout << "Files missing in server: \n";
        for (const auto &file : missing_in_server) {
            std::cout << file << "\n";
        }
    }

    void handlePull() {
        // Send PULL command and handle response
        sendMessage("PULL");
        std::string response = receiveMessage();
        if (!response.empty()) {
            std::cout << "Pull Response: " << response << std::endl;
        }
    }

    void handleLeave() {
        // Send LEAVE command and close connection
        sendMessage("LEAVE");
        std::cout << "Disconnecting from server..." << std::endl;
    }

private:
    int sock;
    struct sockaddr_in serv_addr;
};

int main() {
    try {
        ClientConnection client(SERVER_IP, PORT);
        client.connectToServer();

        std::string command;
        while (true) {
            std::cout << "Enter command (LIST, DIFF, PULL, LEAVE): ";
            std::getline(std::cin, command);

            if (command == "LIST") {
                client.handleListFiles();
            } else if (command == "DIFF") {
                client.handleDiff();
            } else if (command == "PULL") {
                client.handlePull();
            } else if (command == "LEAVE") {
                client.handleLeave();
                break;
            } else {
                std::cout << "Unknown command. Please enter one of the following: LIST, DIFF, PULL, LEAVE." << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return -1;
    }

    return 0;
}
