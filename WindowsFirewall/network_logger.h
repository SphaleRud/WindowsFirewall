#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <chrono>
#include "types.h"

class NetworkLogger {
public:
    NetworkLogger();
    ~NetworkLogger();

    bool Initialize(const std::string& logPath = "network_events.log");
    bool LogPacket(const PacketInfo& packet, const std::string& ruleApplied);
    void Close();

private:
    std::string GetCurrentTimestamp() const;
    std::string FormatPacketInfo(const PacketInfo& packet, const std::string& ruleApplied) const;

    std::ofstream logFile;
    std::mutex logMutex;
    std::string logPath;
};