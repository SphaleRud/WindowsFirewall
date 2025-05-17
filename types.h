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
    std::wstring time;
    std::wstring sourceIP;
    std::wstring destIP;
    std::wstring protocol;
    std::wstring action;
};

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

struct TCPHeader {
    unsigned short sourcePort;
    unsigned short destPort;
    unsigned long sequence;
    unsigned long acknowledge;
    unsigned char offset : 4;
    unsigned char reserved : 4;
    unsigned char flags;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgentPointer;
};
#pragma pack(pop)

