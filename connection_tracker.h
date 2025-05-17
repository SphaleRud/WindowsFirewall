#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <map>
#include "types.h"

struct ConnectionKey {
    std::string sourceIp;
    std::string destIp;
    uint16_t sourcePort;
    uint16_t destPort;
    std::string protocol;
    std::string direction;

    bool operator<(const ConnectionKey& other) const {
        return std::tie(sourceIp, destIp, sourcePort, destPort, protocol, direction) <
            std::tie(other.sourceIp, other.destIp, other.sourcePort, other.destPort, other.protocol, other.direction);
    }
};

struct ConnectionInfo {
    uint64_t packetsCount;
    uint64_t bytesSent;
    std::string application;
    std::string service;
    SYSTEMTIME lastSeen;
};

class ConnectionTracker {
public:
    void AddPacket(const PacketInfo& packet);
    void Clear();
    const std::map<ConnectionKey, ConnectionInfo>& GetConnections() const { return connections; }

private:
    std::map<ConnectionKey, ConnectionInfo> connections;
    static std::string DetermineService(uint16_t port, const std::string& protocol);
};