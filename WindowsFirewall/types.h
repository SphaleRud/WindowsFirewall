#pragma once
#include <string>
#include <vector>
#include <ctime>
#include <Windows.h>
#include <algorithm>
#include "rule.h"
#include "firewall_types.h"
#include "connection.h"
#include <map>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define RCVALL_ON 1

enum class ProtocolFilter
{
    All,
    TCP_UDP,
    TCP,
    UDP
};

enum class FilterMode {
    BLACKLIST,  // ����������� ��������� �������
    WHITELIST   // ��������� ������ ��������� �������
};

struct AppSettings
{
    ProtocolFilter protocolFilter = ProtocolFilter::All;
    FilterMode filterMode;          // ����� ����

    AppSettings() :
        protocolFilter(ProtocolFilter::All),
        filterMode(FilterMode::BLACKLIST)
    {
    }
};

// ��������� �������� ������
#pragma pack(push, 1)
struct IPHeader {
    uint8_t  version_header;  // Version (4 bits) + Internet header length (4 bits)
    uint8_t  typeOfService;   // Type of service
    uint16_t totalLength;     // Total length
    uint16_t id;             // Identification
    uint16_t fragmentOffset;  // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  timeToLive;     // Time to live
    uint8_t  protocol;       // Protocol
    uint16_t checksum;       // Header checksum
    uint32_t sourceIP;       // Source address
    uint32_t destIP;         // Destination address
};

struct TCPHeader {
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgementNumber;
    uint8_t  dataOffset;    // Data offset (4 bits) + Reserved (4 bits)
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgentPointer;
};

struct UDPHeader {
    uint16_t sourcePort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
};
#pragma pack(pop)

#define ICMP_ECHOREPLY      0
#define ICMP_ECHO           8
#define ICMP_DEST_UNREACH   3
#define ICMP_TIME_EXCEEDED 11

struct icmp_header {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
    unsigned short id;
    unsigned short sequence;
};

// ��������� ������������
struct Configuration {
    bool enabled;
    bool logEnabled;
    std::string logPath;

    Configuration()
        : enabled(true)
        , logEnabled(false)
        , logPath("")
    {
    }
};

struct ConnectionKey {
    std::string sourceIp;
    std::string destIp;
    unsigned short sourcePort;
    unsigned short destPort;
    std::string protocol;

    bool operator==(const ConnectionKey& other) const {
        return sourceIp == other.sourceIp &&
            destIp == other.destIp &&
            sourcePort == other.sourcePort &&
            destPort == other.destPort &&
            protocol == other.protocol;
    }
};

// ��������� ��� ����������� � �����������
struct LogEntry {
    time_t timestamp;
    std::string sourceIp;
    std::string destIp;
    uint16_t sourcePort;
    uint16_t destPort;
    Protocol protocol;
    RuleAction action;
    int ruleId;
};

struct NetworkAdapter {
    std::string name;
    std::string description;
};

struct AdapterInfo {
    std::string name;        // ��� ��������
    std::string description; // �������� ��������
    std::string address;     // IP �����
    bool isActive;          // ������� �� �������
};

struct PacketInfo {
    std::string sourceIp;
    std::string destIp;
    std::string protocol;
    std::string processName;
    std::string time;
    std::string sourceDomain;
    std::string destDomain;
    size_t size;
    uint16_t sourcePort;
    uint32_t  processId;
    uint16_t destPort;
    PacketDirection direction;

    PacketInfo() :
        processId(0),
        size(0),
        sourcePort(0),
        destPort(0),
        direction(PacketDirection::Incoming)
    {
    }
};


struct GroupedPacketInfo {
    std::string sourceIp;
    std::string destIp;
    std::string protocol;
    std::string processName;
    std::string processPath;
    std::string time;
    std::string sourceDomain;
    std::string destDomain;
    uint32_t processId;
    uint16_t sourcePort;
    uint16_t destPort;
    PacketDirection direction;
    size_t size;
    uint64_t totalSize;      // ����� ������ ���� �������
    uint32_t packetCount;    // ���������� ������� � ������

    // ���� ��� ����������� (������ � processId, ��������������� processName)
    std::string GetKey() const {
        auto norm = [](const std::string& s) -> std::string {
            std::string r = s;
            // � ������� ��������
            std::transform(r.begin(), r.end(), r.begin(), ::tolower);
            // ������� ������� �� �����
            auto first = r.find_first_not_of(" \t");
            auto last = r.find_last_not_of(" \t");
            if (first == std::string::npos || last == std::string::npos)
                return "";
            return r.substr(first, last - first + 1);
            };

        std::string pname = norm(processName);
        std::string proto = norm(protocol);
        std::string sip = norm(sourceIp);
        std::string dip = norm(destIp);

        return sip + ":" + std::to_string(sourcePort) + "_" +
            dip + ":" + std::to_string(destPort) + "_" +
            proto + "_" +
            pname + "_" +
            std::to_string(processId) + "_" +
            (direction == PacketDirection::Incoming ? "in" : "out");
    }
    GroupedPacketInfo() : processId(0), sourcePort(0), destPort(0),
        totalSize(0), packetCount(0),
        direction(PacketDirection::Incoming) {
    }
};

namespace std {
    template<>
    struct hash<ConnectionKey> {
        size_t operator()(const ConnectionKey& key) const {
            size_t h1 = hash<string>()(key.sourceIp);
            size_t h2 = hash<string>()(key.destIp);
            size_t h3 = hash<unsigned short>()(key.sourcePort);
            size_t h4 = hash<unsigned short>()(key.destPort);
            size_t h5 = hash<string>()(key.protocol);
            return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
        }
    };
}