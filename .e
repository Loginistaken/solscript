#include <iostream>
#include <vector>
#include <ctime>
#include <sstream>
#include <string>
#include <thread>
#include <mutex>
#include <map>
#include <boost/asio.hpp>

using namespace std;
using namespace boost::asio;

mutex blockchainMutex;

class Block {
public:
    int index;
    time_t timestamp;
    string prevHash;
    string hash;
    string data;

    Block(int idx, string prevHash, string data) {
        this->index = idx;
        this->timestamp = time(0);
        this->prevHash = prevHash;
        this->data = data;
        this->hash = calculateHash();
    }

    string calculateHash() {
        stringstream ss;
        ss << index << timestamp << prevHash << data;
        return to_string(hash<string>{}(ss.str()));
    }
};

class Blockchain {
public:
    vector<Block> chain;
    Blockchain() {
        chain.emplace_back(Block(0, "0", "Genesis Block"));
    }
    void addBlock(string data) {
        lock_guard<mutex> lock(blockchainMutex);
        chain.emplace_back(Block(chain.size(), chain.back().hash, data));
    }
};

class P2PNetwork {
public:
    io_service ioService;
    P2PNetwork() {}
    void startServer(int port) {
        ip::tcp::acceptor acceptor(ioService, ip::tcp::endpoint(ip::tcp::v4(), port));
        while (true) {
            ip::tcp::socket socket(ioService);
            acceptor.accept(socket);
            cout << "Connection received" << endl;
        }
    }
};

void runMining(Blockchain &blockchain) {
    while (true) {
        this_thread::sleep_for(chrono::seconds(5));
        blockchain.addBlock("New transaction block");
        cout << "Mined a new block!" << endl;
    }
}

int main() {
    Blockchain blockchain;
    P2PNetwork network;

    thread miningThread(runMining, ref(blockchain));
    thread serverThread(&P2PNetwork::startServer, &network, 8080);

    miningThread.join();
    serverThread.join();

    return 0;
}
// Hashing Function
string sha256(const string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.length(), hash);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << (int)hash[i];
    }
    return ss.str();
}

// Block Structure
struct Block {
    int index;
    string previousHash;
    string timestamp;
    string data;
    string hash;

    Block(int idx, string prevHash, string info) {
        index = idx;
        previousHash = prevHash;
        timestamp = to_string(time(0));
        data = info;
        hash = sha256(to_string(index) + previousHash + timestamp + data);
    }
};

// Blockchain Class
class Blockchain {
public:
    vector<Block> chain;

    Blockchain() {
        chain.emplace_back(Block(0, "0", "Genesis Block"));
    }

    void addBlock(string data) {
        Block newBlock(chain.size(), chain.back().hash, data);
        chain.push_back(newBlock);
    }

    void displayChain() {
        for (const auto& block : chain) {
            cout << "Index: " << block.index << "\nPrevious Hash: " << block.previousHash << "\nTimestamp: " << block.timestamp << "\nData: " << block.data << "\nHash: " << block.hash << "\n\n";
        }
    }
};

// Main Execution
int main() {
    Blockchain myCoin;
    myCoin.addBlock("First Transaction: Coin Ox Address - 0xABC123, Ox ID - 0xDEF456");
    myCoin.displayChain();
    return 0;
}
// Function to create SHA-256 hash
std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str.c_str(), str.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << (int)hash[i];
    }
    return ss.str();
}

// Block structure
struct Block {
    int index;
    std::string prevHash;
    std::string data;
    time_t timestamp;
    std::string hash;
    int nonce;

    // Constructor
    Block(int idx, std::string prev, std::string d) : index(idx), prevHash(prev), data(d), nonce(0) {
        timestamp = time(nullptr);
        hash = calculateHash();
    }

    // Hash calculation
    std::string calculateHash() {
        std::stringstream ss;
        ss << index << prevHash << data << timestamp << nonce;
        return sha256(ss.str());
    }

    // Proof-of-Work: Find a hash with leading zeros
    void mineBlock(int difficulty) {
        std::string target(difficulty, '0');
        while (hash.substr(0, difficulty) != target) {
            nonce++;
            hash = calculateHash();
        }
        std::cout << "Block Mined: " << hash << std::endl;
    }
};

// Blockchain structure
class Blockchain {
public:
    std::vector<Block> chain;
    int difficulty;

    Blockchain(int diff = 2) : difficulty(diff) {
        chain.emplace_back(Block(0, "0", "Genesis Block"));
    }

    void addBlock(std::string data) {
        Block newBlock(chain.size(), chain.back().hash, data);
        newBlock.mineBlock(difficulty);
        chain.push_back(newBlock);
    }
};

int main() {
    Blockchain myCoin;
    
    std::cout << "Mining block 1..." << std::endl;
    myCoin.addBlock("Transaction Data: Alice -> Bob");
    
    std::cout << "Mining block 2..." << std::endl;
    myCoin.addBlock("Transaction Data: Bob -> Charlie");
    
    return 0;
}
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

// Function to simulate Mining configuration (using a thread for multitasking)
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
    displayMITLicense();
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
