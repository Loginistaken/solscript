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
#include <nlohmann/json.hpp> // JSON library for API interaction
#include "web3cpp.h" // Web3 C++ library for Solidity interaction

using namespace boost::asio;
using ip::tcp;
using json = nlohmann::json;

std::mutex mtx;  // Mutex for thread safety
std::queue<std::string> transactionQueue;  // Simple transaction queue

// Blockchain Network Configurations
struct BlockchainConfig {
    std::string coinName = "SolScriptCoin";
    std::string oxAddress;
    std::string oxID;
    std::string genesisBlock;
    double totalSupply = 1000000000000; // Total supply in base units
    double burnRate = 0.02;
    double ownerVault = 1000000000;
    int decimals = 1; // 1 decimal place (1e1 representation)
};

// Transaction Structure
struct Transaction {
    std::string sender;
    std::string receiver;
    double amount;

    // Convert amount to string with decimals
    std::string toString(int decimals) const {
        std::ostringstream oss;
        oss.precision(decimals);
        oss << std::fixed << "Sender: " << sender << " | Receiver: " << receiver << " | Amount: " << amount / std::pow(10, decimals);
        return oss.str();
    }
};
// Function to add a transaction to the queue
void addTransaction(const Transaction& tx, int decimals) {
    std::lock_guard<std::mutex> lock(mtx);
    transactionQueue.push(tx.toString(decimals));
    std::cout << "Transaction added to queue: " << tx.toString(decimals) << std::endl;
}
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
// Function to create the Genesis Block (blockchain's first block)
void createGenesisBlock(BlockchainConfig& config) {
    config.genesisBlock = "Genesis Block for " + config.coinName;
    std::cout << "Genesis Block Created: " << config.genesisBlock << std::endl;
    std::cout << "Total Supply (adjusted for decimals): " << config.totalSupply / std::pow(10, config.decimals) << " " << config.coinName << std::endl;
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

// Function to integrate Solidity
void deploySolidityContract(const std::string& contractSource) {
    web3::Web3 web3("http://localhost:8545"); // Connect to Ethereum node
    std::string bytecode = web3.compileSolidity(contractSource); // Compile contract
    std::string contractAddress = web3.deployContract(bytecode); // Deploy contract
    std::cout << "Deployed Solidity Contract at address: " << contractAddress << std::endl;
}

// Function to expose APIs for JavaScript
void startHTTPServer() {
    io_service ioService;
    tcp::acceptor acceptor(ioService, tcp::endpoint(tcp::v4(), 8081));
    std::cout << "HTTP Server listening on port 8081...\n";

    while (true) {
        tcp::socket socket(ioService);
        acceptor.accept(socket);

        std::string message = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"message\": \"Welcome to SolScript HTTP API\"}";
        boost::asio::write(socket, boost::asio::buffer(message));

        std::cout << "HTTP API accessed. Response sent.\n";
    }
}

// Function to parse and execute SolScript files
void executeSolScript(const std::string& scriptPath) {
    std::ifstream file(scriptPath);
    if (!file.is_open()) {
        std::cerr << "Failed to open SolScript file: " << scriptPath << std::endl;
        return;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    // Simple parsing logic (expand as needed)
    if (content.find("contract") != std::string::npos) {
        std::cout << "Deploying Solidity contract from SolScript...\n";
        deploySolidityContract(content);
    } else {
        std::cout << "Executing JavaScript logic from SolScript...\n";
        // Add JavaScript execution logic here
    }
}

int main() {
    // Start blockchain setup
    autoDeployment();

    // Start HTTP server for JavaScript API
    std::thread httpServerThread(startHTTPServer);

    // Execute a sample SolScript file
    executeSolScript("sample.solscript");

    httpServerThread.join();
    return 0;
}
