#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <functional>
#include <string>
#include <unordered_map>
#include <mutex>
#include "types.h"

struct ConnectionKey {
    std::wstring sourceIP;
    std::wstring destIP;
    std::wstring protocol;

    bool operator==(const ConnectionKey& other) const {
        return sourceIP == other.sourceIP &&
            destIP == other.destIP &&
            protocol == other.protocol;
    }
};

struct ConnectionKeyHash {
    size_t operator()(const ConnectionKey& key) const {
        return std::hash<std::wstring>()(key.sourceIP) ^
            std::hash<std::wstring>()(key.destIP) ^
            std::hash<std::wstring>()(key.protocol);
    }
};

struct ConnectionInfo {
    int packetCount;
    std::wstring lastSeen;
    std::wstring description;
    time_t lastUpdate;
};

struct NetworkAdapter {
    std::wstring name;
    std::wstring description;
    std::string ipAddress;
    bool isWifi;
};

class PacketInterceptor {
public:
    PacketInterceptor();
    ~PacketInterceptor();
    std::vector<NetworkAdapter> GetNetworkAdapters();
    bool Initialize(const std::string& preferredAdapterIp = "");  // Оставляем только одну версию с параметром по умолчанию
    bool StartCapture();
    void StopCapture();

    void SetPacketCallback(std::function<void(const PacketInfo&)> callback) {
        packetCallback = callback;
    }

    std::wstring GetConnectionDescription(const PacketInfo& info) {
        ConnectionKey key{ info.sourceIP, info.destIP, info.protocol };
        std::lock_guard<std::mutex> lock(connectionsMutex);
        auto it = connections.find(key);
        if (it != connections.end()) {
            return it->second.description;
        }
        return L"Unknown";
    }

    

private:
    bool isRunning;
    SOCKET rawSocket;
    HANDLE captureThreadHandle;
    std::function<void(const PacketInfo&)> packetCallback;

    std::unordered_map<ConnectionKey, ConnectionInfo, ConnectionKeyHash> connections;
    std::mutex connectionsMutex;

    static DWORD WINAPI CaptureThread(LPVOID param);
    void ProcessPacket(const char* buffer, int length);
    std::wstring GetProtocolName(IPPROTO protocol);
    std::wstring ResolveDestination(const std::wstring& ip);
    void UpdateConnection(const PacketInfo& info);

    bool IsWifiAdapter(PIP_ADAPTER_ADDRESSES adapter);
};