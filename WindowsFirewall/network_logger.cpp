#include "network_logger.h"
#include <sstream>
#include <iomanip>

NetworkLogger::NetworkLogger() {
    OutputDebugStringA("NetworkLogger constructor called\n");
}

NetworkLogger::~NetworkLogger() {
    Close();
}

bool NetworkLogger::Initialize(const std::string& path) {
    std::lock_guard<std::mutex> lock(logMutex);
    OutputDebugStringA(("Initializing logger with path: " + path + "\n").c_str());

    try {
        logPath = path;
        logFile.open(logPath, std::ios::app);

        if (!logFile.is_open()) {
            OutputDebugStringA(("Failed to open log file: " + logPath + "\n").c_str());
            return false;
        }

        // Записываем заголовок при создании нового файла
        if (logFile.tellp() == 0) {
            logFile << "Timestamp,Direction,Protocol,SourceIP,SourcePort,DestIP,DestPort,ProcessID,ProcessName,RuleApplied\n";
            logFile.flush();
        }

        OutputDebugStringA("Logger initialized successfully\n");
        return true;
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("Logger initialization failed: " + std::string(e.what()) + "\n").c_str());
        return false;
    }
}

bool NetworkLogger::LogPacket(const PacketInfo& packet, const std::string& ruleApplied) {
    try {
        std::lock_guard<std::mutex> lock(logMutex);
        if (logFile.is_open()) {
            std::string logEntry = FormatPacketInfo(packet, ruleApplied);
            logFile << logEntry << std::endl;
            logFile.flush();
            OutputDebugStringA(("Logged: " + logEntry + "\n").c_str());
            return true;
        }
        OutputDebugStringA("Log file is not open\n");
        return false;
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("Error logging packet: " + std::string(e.what()) + "\n").c_str());
        return false;
    }
}

void NetworkLogger::Close() {
    std::lock_guard<std::mutex> lock(logMutex);
    if (logFile.is_open()) {
        logFile.close();
    }
}

std::string NetworkLogger::GetCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    return ss.str();
}

std::string NetworkLogger::FormatPacketInfo(const PacketInfo& packet, const std::string& ruleApplied) const {
    std::stringstream ss;
    ss << GetCurrentTimestamp() << ","
        << (packet.direction == PacketDirection::Incoming ? "Incoming" : "Outgoing") << ","
        << packet.protocol << ","
        << packet.sourceIp << ","
        << packet.sourcePort << ","
        << packet.destIp << ","
        << packet.destPort << ","
        << packet.processId << ","
        << packet.processName << ","
        << ruleApplied;

    return ss.str();
}