#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "firewall_types.h"

// Максимальные размеры для строковых полей
#define MAX_PATH_LENGTH 260
#define MAX_IP_LENGTH 46    // Достаточно для IPv6
#define MAX_PROTO_LENGTH 8  // TCP, UDP, ICMP, ANY

#pragma pack(push, 1)
// Структура для информации о блокированном пакете
struct BlockedPacketEntry {
    char processName[MAX_PATH_LENGTH];
    char sourceIp[MAX_IP_LENGTH];
    char destIp[MAX_IP_LENGTH];
    uint16_t sourcePort;
    uint16_t destPort;
    char protocol[MAX_PROTO_LENGTH];
    int ruleId;
    FILETIME timestamp;     // Время блокировки
    bool isValid;           // Флаг валидности записи
};

// Структура заголовка разделяемой памяти
struct SharedMemoryHeader {
    DWORD maxEntries;       // Максимальное количество записей
    DWORD currentCount;     // Текущее количество записей
    DWORD writeIndex;       // Индекс для записи
    DWORD readIndex;        // Индекс для чтения
};
#pragma pack(pop)

// Размер кольцевого буфера
#define BLOCKED_PACKETS_BUFFER_SIZE 1000

// Полный размер разделяемой памяти
#define SHARED_MEMORY_SIZE (sizeof(SharedMemoryHeader) + \
                          (BLOCKED_PACKETS_BUFFER_SIZE * sizeof(BlockedPacketEntry)))