#pragma once
#include <windows.h>
#include "shared_types.h"
#include <string>

class SharedMemoryManager {
public:
    static SharedMemoryManager& Instance() {
        static SharedMemoryManager instance;
        return instance;
    }

    bool Initialize(bool isProducer) {
        m_isProducer = isProducer;

        // Создаём/открываем объекты синхронизации
        m_mutex = CreateMutexW(NULL, FALSE, L"Global\\FirewallBlockedPacketsMutex");
        if (m_mutex == NULL) {
            OutputDebugStringA("Failed to create/open mutex\n");
            return false;
        }

        // Создаём/открываем разделяемую память
        m_hMapFile = isProducer ?
            CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                0, SHARED_MEMORY_SIZE, L"Global\\FirewallBlockedPackets") :
            OpenFileMappingW(FILE_MAP_READ, FALSE, L"Global\\FirewallBlockedPackets");

        if (m_hMapFile == NULL) {
            OutputDebugStringA("Failed to create/open file mapping\n");
            CloseHandle(m_mutex);
            m_mutex = NULL;
            return false;
        }

        // Отображаем память
        m_pSharedMemory = MapViewOfFile(m_hMapFile,
            isProducer ? FILE_MAP_WRITE : FILE_MAP_READ,
            0, 0, SHARED_MEMORY_SIZE);

        if (m_pSharedMemory == NULL) {
            OutputDebugStringA("Failed to map view of file\n");
            CloseHandle(m_hMapFile);
            CloseHandle(m_mutex);
            m_hMapFile = NULL;
            m_mutex = NULL;
            return false;
        }

        // Инициализируем заголовок если мы продюсер
        if (isProducer) {
            SharedMemoryHeader* header = (SharedMemoryHeader*)m_pSharedMemory;
            header->maxEntries = BLOCKED_PACKETS_BUFFER_SIZE;
            header->currentCount = 0;
            header->writeIndex = 0;
            header->readIndex = 0;
        }

        return true;
    }

    bool AddBlockedPacket(const BlockedPacketEntry& entry) {
        if (!m_isProducer || !m_pSharedMemory) return false;

        WaitForSingleObject(m_mutex, INFINITE);

        SharedMemoryHeader* header = (SharedMemoryHeader*)m_pSharedMemory;
        BlockedPacketEntry* entries = (BlockedPacketEntry*)((char*)m_pSharedMemory + sizeof(SharedMemoryHeader));

        // Добавляем запись в кольцевой буфер
        entries[header->writeIndex] = entry;

        // Обновляем индексы
        header->writeIndex = (header->writeIndex + 1) % header->maxEntries;
        if (header->currentCount < header->maxEntries)
            header->currentCount++;

        ReleaseMutex(m_mutex);
        return true;
    }

    std::vector<BlockedPacketEntry> GetBlockedPackets() {
        std::vector<BlockedPacketEntry> result;
        if (!m_pSharedMemory) return result;

        WaitForSingleObject(m_mutex, INFINITE);

        SharedMemoryHeader* header = (SharedMemoryHeader*)m_pSharedMemory;
        BlockedPacketEntry* entries = (BlockedPacketEntry*)((char*)m_pSharedMemory + sizeof(SharedMemoryHeader));

        // Читаем все доступные записи
        for (DWORD i = 0; i < header->currentCount; i++) {
            DWORD index = (header->readIndex + i) % header->maxEntries;
            if (entries[index].isValid) {
                result.push_back(entries[index]);
            }
        }

        // Обновляем индекс чтения
        if (!m_isProducer) {
            header->readIndex = header->writeIndex;
            header->currentCount = 0;
        }

        ReleaseMutex(m_mutex);
        return result;
    }

    ~SharedMemoryManager() {
        if (m_pSharedMemory) {
            UnmapViewOfFile(m_pSharedMemory);
        }
        if (m_hMapFile) {
            CloseHandle(m_hMapFile);
        }
        if (m_mutex) {
            CloseHandle(m_mutex);
        }
    }

private:
    HANDLE m_hMapFile;
    LPVOID m_pSharedMemory;
    HANDLE m_mutex;
    bool m_isProducer;

    SharedMemoryManager() : m_hMapFile(NULL), m_pSharedMemory(NULL),
        m_mutex(NULL), m_isProducer(false) {
    }
};