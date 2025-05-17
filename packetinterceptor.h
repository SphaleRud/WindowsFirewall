#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <mutex>
#include <map>
#include <functional>
#include "types.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

class PacketInterceptor {
public:
    PacketInterceptor();
    virtual ~PacketInterceptor();

    bool Initialize(const std::string& preferredAdapterIp = "");
    bool StartCapture();
    void StopCapture();
    bool SwitchAdapter(const std::string& ipAddress);
    void SetPacketCallback(const std::function<void(const PacketInfo&)>& callback);
    std::vector<NetworkAdapter> GetNetworkAdapters();

    // Пример конвертации, если она необходима
    std::string WideToAnsi(const wchar_t* wstr) {
        if (!wstr) return "";

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, nullptr, nullptr);
        if (!strTo.empty() && strTo.back() == 0) {
            strTo.pop_back(); // Удаляем завершающий нуль
        }
        return strTo;
    }
protected:
    bool IsLocalAddress(const std::string& ipAddress);
    std::string GetProcessNameById(DWORD processId);
    DWORD GetProcessIdByPort(WORD port, const std::string& protocol);
    void ProcessPacket(const char* data, int size);
    std::string ResolveDestination(const std::string& ip);
private:
    bool isRunning;
    SOCKET rawSocket;
    HANDLE captureThreadHandle;
    std::function<void(const PacketInfo&)> packetCallback;
    std::mutex connectionsMutex;

    static DWORD WINAPI CaptureThread(LPVOID param);
    std::wstring GetProtocolName(IPPROTO protocol);
    void UpdateConnection(const PacketInfo& info);

    bool IsWifiAdapter(PIP_ADAPTER_ADDRESSES adapter);
};