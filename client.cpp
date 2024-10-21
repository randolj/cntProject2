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
#include <random>

#define PORT 4321
#define SERVER_IP "127.0.0.1"

namespace fs = std::filesystem;
std::string client_music_dir = "./client_files/";


class ClientConnection {
public:
    ClientConnection(const std::string& ip, int port) {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (!fs::exists(client_music_dir)) {
            std::cout << "Directory " << client_music_dir << " does not exist. Creating..." << std::endl;
            fs::create_directories(client_music_dir);
        }

        client_token = get_client_token();

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
        sendMessage(client_token);
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

        if (response == "empty") {
            std::cout << "Server is empty!" << std::endl;
        }
        else if (!response.empty()) {
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
            if (file_name == "client_token.txt") {
                continue;
            }
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

        if (missing_in_client.empty() && missing_in_server.empty()) {
            std::cout << "Client and Server are up to date!" << std::endl;
        }
        else if (missing_in_client.empty()) {
            std::cout << "Client is up to date" << std::endl;

            std::cout << "Files missing in server:" << std::endl;
            for (const auto &file : missing_in_server) {
                std::cout << file << std::endl;
            }
        }
        else if (missing_in_server.empty()) {
            std::cout << "Server is up to date!" << std::endl;
            std::cout << "Files missing in client:" << std::endl;
            for (const auto &file : missing_in_client) {
                std::cout << file << std::endl;
            }
        }
        else {
            std::cout << "Files missing in client:" << std::endl;
            for (const auto &file : missing_in_client) {
                std::cout << file << std::endl;
            }
            std::cout << "Files missing in server:" << std::endl;
            for (const auto &file : missing_in_server) {
                std::cout << file << std::endl;
            }
        }
    }

    void handlePull() {
    // Send PULL command and handle response
    sendMessage("PULL");
    std::string server_file_list = receiveMessage();

    // Get client files and hashes
    std::vector<std::pair<std::string, std::string>> client_files;
    for (const auto &entry : fs::directory_iterator(client_music_dir)) {
        std::string file_name = entry.path().filename().string();
        if (file_name == "client_token.txt") {
            continue;
        }
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

    std::cout << "Files missing in client:" << std::endl;
    for (const auto &file : missing_in_client) {
        std::cout << file << std::endl;
    }
    std::cout << "Trying to fetch files from server..." << std::endl;
    sendMessage(std::to_string(missing_in_client.size()));

    for (const auto &file : missing_in_client) {
        sendMessage(file);

        // Receive the file size from the server
        std::string file_size_str = receiveMessage();
        size_t file_size = std::stoull(file_size_str);

        // Get the path for saving the file, checking if a file with the same name exists
        std::string save_path = get_unique_file_path(client_music_dir + file);

        std::ofstream out_file(save_path, std::ios::binary);
        if (!out_file) {
            std::cerr << "Failed to create file: " << save_path << std::endl;
            continue;
        }

        std::cout << "Receiving file: " << file << " (" << file_size << " bytes) as " << save_path << std::endl;

        // Receive the file in chunks
        size_t received_bytes = 0;
        char buffer[1024];
        while (received_bytes < file_size) {
            int bytes_read = read(sock, buffer, sizeof(buffer));
            if (bytes_read <= 0) {
                std::cerr << "Error reading from server or connection lost." << std::endl;
                break;
            }

            // Writing to the file
            out_file.write(buffer, bytes_read);
            received_bytes += bytes_read;
        }

        out_file.close();
        std::cout << "File received successfully: " << save_path << std::endl;
    }

}

// Helper function to check if the file exists and generate a unique name if necessary
std::string get_unique_file_path(const std::string& file_path) {
    if (!fs::exists(file_path)) {
        return file_path;  // If the file does not exist, return the original path
    }

    // If file exists, generate a new file name with a counter (e.g., "file (1).ext")
    std::string base_name = file_path;
    std::string extension;
    size_t dot_pos = file_path.find_last_of(".");
    if (dot_pos != std::string::npos) {
        base_name = file_path.substr(0, dot_pos);
        extension = file_path.substr(dot_pos);
    }

    int counter = 1;
    std::string new_file_path;
    do {
        new_file_path = base_name + " (" + std::to_string(counter++) + ")" + extension;
    } while (fs::exists(new_file_path));  // Keep checking until we find a non-existing file name

    return new_file_path;
}

    void handleLeave() {
        // Send LEAVE command and close connection
        sendMessage("LEAVE");
        std::cout << "Disconnecting from server..." << std::endl;
    }



    //generate or get token
    std::string get_client_token() {
        std::string token_file = client_music_dir + "client_token.txt";
        std::ifstream infile(token_file);
        std::string token;

        if (infile.good()) {
            std::getline(infile, token);
            infile.close();
        } else {
            token = generate_token();
            std::ofstream outfile(token_file);
            outfile << token;
            outfile.close();
        }

        return token;
    }

private:
    int sock;
    struct sockaddr_in serv_addr;
    std::string client_token;

    //generate token
    std::string generate_token() {
        const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789";
        const int token_length = 6;
        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

        std::string token;
        for (int i = 0; i < token_length; i++) {
            token += charset[dist(generator)];
        }
        return token;
    }

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
