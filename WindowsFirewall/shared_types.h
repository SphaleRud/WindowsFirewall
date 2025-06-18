#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "firewall_types.h"

// ������������ ������� ��� ��������� �����
#define MAX_PATH_LENGTH 260
#define MAX_IP_LENGTH 46    // ���������� ��� IPv6
#define MAX_PROTO_LENGTH 8  // TCP, UDP, ICMP, ANY

#pragma pack(push, 1)
// ��������� ��� ���������� � ������������� ������
struct BlockedPacketEntry {
    char processName[MAX_PATH_LENGTH];
    char sourceIp[MAX_IP_LENGTH];
    char destIp[MAX_IP_LENGTH];
    uint16_t sourcePort;
    uint16_t destPort;
    char protocol[MAX_PROTO_LENGTH];
    int ruleId;
    FILETIME timestamp;     // ����� ����������
    bool isValid;           // ���� ���������� ������
};

// ��������� ��������� ����������� ������
struct SharedMemoryHeader {
    DWORD maxEntries;       // ������������ ���������� �������
    DWORD currentCount;     // ������� ���������� �������
    DWORD writeIndex;       // ������ ��� ������
    DWORD readIndex;        // ������ ��� ������
};
#pragma pack(pop)

// ������ ���������� ������
#define BLOCKED_PACKETS_BUFFER_SIZE 1000

// ������ ������ ����������� ������
#define SHARED_MEMORY_SIZE (sizeof(SharedMemoryHeader) + \
                          (BLOCKED_PACKETS_BUFFER_SIZE * sizeof(BlockedPacketEntry)))