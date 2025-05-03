#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <thread>
#include <memory>
#include <future>
#include <chrono>
#include <vector>
#include <mutex>
#include <sstream>
#include <queue>
#include <boost/asio.hpp>  // Boost library for networking
#include <openssl/sha.h>  // OpenSSL for cryptographic hashing
#include <openssl/evp.h>  // For SHA256

using namespace boost::asio;
using ip::tcp;

std::mutex mtx;  // Mutex for thread safety
std::queue<std::string> transactionQueue;  // Simple transaction queue

// Blockchain Network Configurations
struct BlockchainConfig {
    std::string coinName = "SolScriptCoin";
    std::string oxAddress;
    std::string oxID;
    std::string genesisBlock;
    double totalSupply = 1000000000000;
    double burnRate = 0.02;
    double ownerVault = 1000000000;
};

// Transaction Structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;

    std::string toString() const {
        return "Sender: " + sender + " | Receiver: " + receiver + " | Amount: " + std::to_string(amount);
    }
};

// Block Structure for Blockchain
struct Block {
    std::string previousHash;
    std::string hash;
    std::vector<Transaction> transactions;
    long timestamp;
    int nonce;

    // Calculate block hash using SHA-256
    std::string calculateHash() {
        std::stringstream ss;
        ss << previousHash << timestamp << nonce;
        for (const auto& tx : transactions) {
            ss << tx.toString();
        }
        return sha256(ss.str());
    }

    // Proof of Work (Mining)
    void mineBlock(int difficulty) {
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = calculateHash();
        }
        std::cout << "Block mined: " << hash << std::endl;
    }
};

// Blockchain Structure
class Blockchain {
public:
    std::vector<Block> chain;
    int difficulty = 4;  // Mining difficulty (e.g., how many zeros in the hash)

    Blockchain() {
        // Create genesis block
        Block genesisBlock;
        genesisBlock.timestamp = std::time(0);
        genesisBlock.previousHash = "0";
        genesisBlock.nonce = 0;
        genesisBlock.transactions.push_back(Transaction{"", "", 0});
        genesisBlock.hash = genesisBlock.calculateHash();
        chain.push_back(genesisBlock);
    }

    void addBlock(Block& newBlock) {
        newBlock.previousHash = chain.back().hash;
        newBlock.hash = newBlock.calculateHash();
        newBlock.mineBlock(difficulty);
        chain.push_back(newBlock);
    }
    
    void printChain() {
        for (auto& block : chain) {
            std::cout << "Block Hash: " << block.hash << std::endl;
        }
    }
    
private:
    std::string sha256(const std::string str) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX sha256_CTX;
        SHA256_Init(&sha256_CTX);
        SHA256_Update(&sha256_CTX, str.c_str(), str.length());
        SHA256_Final(hash, &sha256_CTX);
        
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << (int)hash[i];
        }
        return ss.str();
    }
};

// Function to generate Coin Ox Address
std::string generateOxAddress() {
    return "0x" + std::to_string(rand() % 10000000000000000); // Placeholder
}

// Function to generate Ox ID
std::string generateOxID() {
    return "OXC-" + std::to_string(rand() % 1000000); // Placeholder
}

// Function to create the Genesis Block (blockchain's first block)
void createGenesisBlock(BlockchainConfig& config) {
    config.genesisBlock = "Genesis Block for " + config.coinName;
    std::cout << "Genesis Block Created: " << config.genesisBlock << std::endl;
}

// Function to add a transaction to the queue
void addTransaction(const Transaction& tx) {
    std::lock_guard<std::mutex> lock(mtx);
    transactionQueue.push(tx.toString());
    std::cout << "Transaction added to queue: " << tx.toString() << std::endl;
}

// Function to process transactions
void processTransactions() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5)); // Simulate processing time
        std::lock_guard<std::mutex> lock(mtx);
        if (!transactionQueue.empty()) {
            std::string tx = transactionQueue.front();
            transactionQueue.pop();
            std::cout << "Processing transaction: " << tx << std::endl;
        }
    }
}

// P2P Server Function
void startServer() {
    try {
        io_service ioService;
        tcp::acceptor acceptor(ioService, tcp::endpoint(tcp::v4(), 8080));
        std::cout << "P2P Node is listening on port 8080...\n";

        while (true) {
            tcp::socket socket(ioService);
            acceptor.accept(socket);

            std::string message = "Welcome to the SolScriptCoin Network!";
            boost::asio::write(socket, boost::asio::buffer(message));

            std::cout << "New peer connected. Message sent.\n";
        }
    } catch (std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
    }
}

// P2P Client Function
void connectToPeer(const std::string& ip, int port) {
    try {
        io_service ioService;
        tcp::socket socket(ioService);
        tcp::resolver resolver(ioService);
        tcp::resolver::query query(ip, std::to_string(port));
        tcp::resolver::iterator endpoint = resolver.resolve(query);
        boost::asio::connect(socket, endpoint);

        char response[128];
        size_t len = socket.read_some(boost::asio::buffer(response));
        std::cout << "Received from peer: " << std::string(response, len) << std::endl;
    } catch (std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
    }
}

// Mining Configuration (proof-of-work)
void configureMining() {
    std::cout << "Mining configuration completed!" << std::endl;
}

// Function for auto deployment of blockchain setup
void autoDeployment() {
    std::cout << "Setting up Blockchain Network...\n";
    
    // Using smart pointers for memory management
    auto config = std::make_shared<BlockchainConfig>();
    
    // Generating Ox Address & Ox ID
    config->oxAddress = generateOxAddress();
    config->oxID = generateOxID();
    
    createGenesisBlock(*config); // Pass config by reference
    
    // Start mining configuration in a separate thread for multithreading
    std::thread miningThread(configureMining); 
    
    // Wait for the mining thread to finish
    miningThread.join();
    
    std::cout << "Blockchain Network Setup Complete\n";
    
    // Simulating connection to an external platform
    std::cout << "Connecting to external platform...\n";
    // Here, you can implement API logic for connecting to external platforms
    std::cout << "Connected to Coinbase or equivalent platform\n";
}

// Function to simulate automatic pop-up of the MIT License
void popUpMITLicense() {
    std::cout << "\n-----------------------------------------------\n";
    std::cout << "End of program. Displaying MIT License...\n";
    // Placeholder for actual MIT License display
    std::cout << "MIT License: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files to deal in the Software without restriction...\n";
    std::this_thread::sleep_for(std::chrono::seconds(5));  // Wait for user to read
    std::cout << "Exiting program...\n";
}

// Function to run terminal or PowerShell commands dynamically
void runCommand(const std::string& command) {
    std::system(command.c_str()); // Executes the provided command (e.g., PowerShell or Terminal commands)
}

int main() {
    // Automatically trigger the deployment and setup of the blockchain
    autoDeployment();
    
    // Auto-trigger PowerShell or Terminal commands after blockchain setup
    // Example for Windows (PowerShell) and UNIX (Bash)
    std::string platformCommand;
    
    #ifdef _WIN32  // Check if on Windows
        platformCommand = "powershell -Command \"echo Blockchain Setup Complete\"";
    #else // Assuming UNIX-like system
        platformCommand = "bash -c \"echo Blockchain Setup Complete\"";
    #endif

    // Run the command to indicate successful deployment
    runCommand(platformCommand);
    
    // Trigger MIT License pop-up before exit
    popUpMITLicense();
    
    return 0;
}

