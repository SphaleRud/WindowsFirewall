#pragma once
#include <string>
#include <vector>
#include <ctime>
#include <Windows.h>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)
#define RCVALL_ON 1

// ������� ������������
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

// ��������� �������� ������
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

struct UDPheader {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short length;
    unsigned short checksum;
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

// ��������� ������ � ����������
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

enum class PacketDirection {
    Incoming = 0,
    Outgoing = 1
};

struct PacketInfo {
    PacketInfo() :
        timestamp(0),
        size(0),
        sourcePort(0),
        destPort(0),
        flags(0) {
        GetSystemTime(&systemTime);
    }

    time_t timestamp;            // ����� ��������� ������
    SYSTEMTIME systemTime;       // ��������� ����� Windows
    std::string sourceIp;        // IP-����� ���������
    std::string destIp;          // IP-����� ����������
    uint16_t sourcePort;         // ���� ���������
    uint16_t destPort;          // ���� ����������
    std::string protocol;        // �������� (TCP, UDP, etc.)
    size_t size;                // ������ ������
    uint32_t flags;             // ����� ������
    PacketDirection direction;   // ����������� ������
    std::string processName;    // ��� ��������
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