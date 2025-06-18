#pragma once
#define HAVE_REMOTE
#define WPCAP
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <functional>
#include <thread>
#include <algorithm>
#include "types.h"
#include <fwpmtypes.h>
#include <fwpmu.h>
#include "string_utils.h"

class PacketInterceptor {
public:
    PacketInterceptor();
    ~PacketInterceptor();

    bool Initialize();

    std::vector<NetworkAdapter> GetNetworkAdapters() const;
    bool SetCurrentAdapter(const std::string& adapterName);
    const std::string& GetCurrentAdapter() const { return currentAdapter; }
    bool StartCapture(const std::string& adapterIp);
    bool StopCapture();
    bool IsCapturing() const { return isCapturing; }

    static bool IsWifiAdapter(const std::string& description) {
        std::string lowerName = description;
        std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
        return lowerName.find("wireless") != std::string::npos ||
            lowerName.find("wifi") != std::string::npos ||
            lowerName.find("802.11") != std::string::npos;
    }

    // Callback для обработки пакетов
    using PacketCallback = std::function<void(const PacketInfo&)>;
    void SetPacketCallback(PacketCallback callback) {
        packetCallback = callback;
    }
    std::vector<AdapterInfo> GetAdapters();
protected:
    void ProcessPacket(const pcap_pkthdr* header, const u_char* packet);
    std::string GetProcessNameByPort(unsigned short port);
    std::string GetProtocolName(u_char protocol);
    std::string GetConnectionDescription(const PacketInfo& info) const;
    void UpdateConnection(const PacketInfo& info);
    std::string ResolveDestination(const std::string& ip) const;
    bool IsOutgoingPacket(const std::string& sourceIp) const;
    std::string GetServiceName(unsigned short port) const;
    static void CaptureThread(PacketInterceptor* interceptor);

private:
    bool IsLocalAddress(const std::string& ip) const;
    bool IsPrivateNetworkAddress(const std::string& ip) const;
    PacketDirection DeterminePacketDirection(const std::string& sourceIp) const;

    pcap_t* handle;
    std::string currentAdapter;
    bool isCapturing;
    std::atomic<bool> isRunning;
    SOCKET rawSocket;
    std::thread captureThread;
    std::unordered_map<std::string, std::string> connections;
    std::unordered_map<unsigned short, std::string> knownServices;
    mutable std::mutex mutex;
    std::function<void(const PacketInfo&)> packetCallback;
};