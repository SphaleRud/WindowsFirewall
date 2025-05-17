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
#include "types.h"

class PacketInterceptor {
public:
    PacketInterceptor();
    ~PacketInterceptor();

    bool Initialize();
    std::vector<NetworkAdapter> GetNetworkAdapters() const;
    bool SetCurrentAdapter(const std::string& adapterName);
    const std::string& GetCurrentAdapter() const { return currentAdapterIp; }
    bool StartCapture();
    bool StopCapture();
    bool IsCapturing() const { return isCapturing; }
    void SetPacketCallback(std::function<void(const PacketInfo&)> callback) {
        std::lock_guard<std::mutex> lock(mutex);
        packetCallback = callback;
    }
    void ProcessPacket(const struct pcap_pkthdr* header, const u_char* pkt_data);

protected:
    std::string GetConnectionDescription(const PacketInfo& info) const;
    bool IsWifiAdapter(const std::string& description) const;
    std::string ResolveDestination(const std::string& ip) const;
    std::string GetProtocolName(int protocol) const;
    void UpdateConnection(const PacketInfo& info);
    std::string GetServiceName(unsigned short port) const;
    void CaptureThread();
    static void PacketHandler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

private:
    SOCKET rawSocket;
    bool IsOutgoingPacket(const std::string& sourceIp) const;
    std::string GetProcessNameByPort(unsigned short port);
    std::string currentAdapterIp;
    std::string adapterName;
    pcap_t* pcapHandle;
    std::thread captureThread;
    pcap_t* handle;
    std::string currentAdapter;
    bool isCapturing;
    bool isRunning;
    std::unordered_map<std::string, std::string> connections;
    std::unordered_map<unsigned short, std::string> knownServices;
    mutable std::mutex mutex;  // Только одно объявление mutex
    std::function<void(const PacketInfo&)> packetCallback;
};