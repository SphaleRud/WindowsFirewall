#pragma once
#include <string>
#include <vector>
#include <ctime>
#include <Windows.h>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define RCVALL_ON 1

// Базовые перечисления
enum class RuleAction {
    ALLOW,
    BLOCK
};

enum class Protocol {
    TCP,
    UDP,
    ICMP,
    ANY
};

// Структуры сетевого уровня
#pragma pack(push, 1)
struct IPHeader {
    unsigned char headerLength : 4;
    unsigned char version : 4;
    unsigned char typeOfService;
    unsigned short totalLength;
    unsigned short id;
    unsigned short fragmentOffset;
    unsigned char timeToLive;
    unsigned char protocol; 
    unsigned short checksum;
    unsigned long sourceIP;
    unsigned long destIP;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct TCPHeader {
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgementNumber;
    uint8_t dataOffset;  // старшие 4 бита
    uint8_t flags;
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

// Структуры правил и соединений
struct Rule {
    int id;
    std::string name;
    std::string sourceIp;
    std::string destIp;
    uint16_t sourcePort;
    uint16_t destPort;
    Protocol protocol;
    RuleAction action;
    bool enabled;
};

struct Connection {
    std::string sourceIp;
    std::string destIp;
    uint16_t sourcePort;
    uint16_t destPort;
    Protocol protocol;
    time_t timestamp;
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

// Структуры для логирования и отображения
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

enum class PacketDirection {
    Incoming,
    Outgoing
};

struct AdapterInfo {
    std::string name;        // Имя адаптера
    std::string description; // Описание адаптера
    std::string address;     // IP адрес
    bool isActive;          // Активен ли адаптер
};

struct PacketInfo {
    std::string sourceIp;
    std::string destIp;
    std::string protocol;
    std::string processName;
    std::string time;
    size_t size;
    uint16_t sourcePort;
    uint16_t destPort;
    PacketDirection direction;

    PacketInfo() :
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
    std::string time;
    uint16_t sourcePort;
    uint16_t destPort;
    PacketDirection direction;

    // Ключ для группировки (убран размер)
    std::string GetKey() const {
        return sourceIp + ":" + std::to_string(sourcePort) + "_" +
            destIp + ":" + std::to_string(destPort) + "_" +
            protocol + "_" + processName + "_" +
            (direction == PacketDirection::Incoming ? "in" : "out");
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