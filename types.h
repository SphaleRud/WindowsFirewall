#pragma once
#include <string>
#include <vector>
#include <ctime>
#include <Windows.h>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define RCVALL_ON 1

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

struct PacketInfo {
    std::string sourceIp;
    std::string destIp;
    uint16_t sourcePort;
    uint16_t destPort;
    std::string protocol;
    uint64_t bytesSent;
    std::string direction;  // "IN" или "OUT"
    std::string application;
    SYSTEMTIME timestamp;
};

struct NetworkAdapter {
    std::string name;
    std::string description;
    std::string ipAddress;
    bool isWifi;
};

#pragma pack(push, 1)
struct IPHeader {
    unsigned char  headerLength : 4;
    unsigned char  version : 4;
    unsigned char  typeOfService;
    unsigned short totalLength;
    unsigned short identification;
    unsigned short fragmentOffset;
    unsigned char  timeToLive;
    unsigned char  protocol;
    unsigned short headerChecksum;
    unsigned long  sourceIP;
    unsigned long  destIP;
};

struct TCPHeader {
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned long  sequenceNumber;
    unsigned long  acknowledgementNumber;
    unsigned char  dataOffset;
    unsigned char  flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgentPointer;
};

struct UDPHeader {
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned short length;
    unsigned short checksum;
};
#pragma pack(pop)
