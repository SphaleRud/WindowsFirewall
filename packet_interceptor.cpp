#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "packetinterceptor.h"
#include "types.h"
#include <time.h>
#include <iphlpapi.h>
#include <iostream>
#include <mutex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

PacketInterceptor::PacketInterceptor() :
    isRunning(false),
    rawSocket(INVALID_SOCKET),
    captureThreadHandle(NULL),
    packetCallback(nullptr) {
}

PacketInterceptor::~PacketInterceptor() {
    StopCapture();
    if (rawSocket != INVALID_SOCKET) {
        closesocket(rawSocket);
        rawSocket = INVALID_SOCKET;
    }
    WSACleanup();
}

std::wstring PacketInterceptor::GetProtocolName(IPPROTO protocol) {
    switch (protocol) {
    case IPPROTO_TCP:
        return L"TCP";
    case IPPROTO_UDP:
        return L"UDP";
    case IPPROTO_ICMP:
        return L"ICMP";
    default:
        return std::to_wstring(static_cast<int>(protocol));
    }
}

bool PacketInterceptor::IsWifiAdapter(PIP_ADAPTER_ADDRESSES adapter) {
    return adapter->IfType == IF_TYPE_IEEE80211;
}

std::vector<NetworkAdapter> PacketInterceptor::GetNetworkAdapters() {
    std::vector<NetworkAdapter> adapters;

    ULONG outBufLen = 0;
    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &outBufLen);

    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if (GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &outBufLen) == ERROR_SUCCESS) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;

        while (pCurrAddresses) {
            if (pCurrAddresses->OperStatus == IfOperStatusUp) {
                PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;

                if (pUnicast != NULL && pUnicast->Address.lpSockaddr != NULL) {
                    NetworkAdapter adapter;

                    // Получаем имя адаптера
                    adapter.name = pCurrAddresses->FriendlyName;
                    adapter.description = pCurrAddresses->Description;
                    adapter.isWifi = IsWifiAdapter(pCurrAddresses);

                    // Получаем IP адрес
                    char ipStr[46];
                    sockaddr_in* sockaddr = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    inet_ntop(AF_INET, &sockaddr->sin_addr, ipStr, sizeof(ipStr));
                    adapter.ipAddress = ipStr;

                    // Исключаем виртуальные адаптеры
                    if (adapter.name.find(L"Radmin") == std::wstring::npos &&
                        adapter.name.find(L"VPN") == std::wstring::npos &&
                        adapter.name.find(L"Virtual") == std::wstring::npos) {
                        adapters.push_back(adapter);
                    }
                }
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    }

    free(pAddresses);
    return adapters;
}

bool PacketInterceptor::Initialize(const std::string& preferredAdapterIp) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }

    // Получаем список адаптеров
    std::vector<NetworkAdapter> adapters = GetNetworkAdapters();
    if (adapters.empty()) {
        WSACleanup();
        return false;
    }

    // Ищем предпочтительный адаптер
    NetworkAdapter* selectedAdapter = nullptr;

    // Сначала ищем по указанному IP
    if (!preferredAdapterIp.empty()) {
        for (auto& adapter : adapters) {
            if (adapter.ipAddress == preferredAdapterIp) {
                selectedAdapter = &adapter;
                break;
            }
        }
    }

    // Если не нашли по IP, ищем Wi-Fi адаптер
    if (!selectedAdapter) {
        for (auto& adapter : adapters) {
            if (adapter.isWifi) {
                selectedAdapter = &adapter;
                break;
            }
        }
    }

    // Если и Wi-Fi не нашли, берем первый доступный
    if (!selectedAdapter && !adapters.empty()) {
        selectedAdapter = &adapters[0];
    }

    if (!selectedAdapter) {
        WSACleanup();
        return false;
    }

    this->rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (this->rawSocket == INVALID_SOCKET) {
        WSACleanup();
        return false;
    }

    // Привязываем сокет к выбранному адаптеру
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    inet_pton(AF_INET, selectedAdapter->ipAddress.c_str(), &addr.sin_addr);

    if (bind(this->rawSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(this->rawSocket);
        WSACleanup();
        return false;
    }

    // Включаем промискуитетный режим
    DWORD optval = 1;
    if (setsockopt(rawSocket, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"Failed to set IP_HDRINCL. Error code: %d", error);
        MessageBox(NULL, errorMsg, L"Error", MB_OK | MB_ICONERROR);
        closesocket(rawSocket);
        WSACleanup();
        return false;
    }

    // Включаем режим SIO_RCVALL
    DWORD rcvall = RCVALL_ON;
    DWORD bytesReturned = 0;
    if (WSAIoctl(rawSocket, SIO_RCVALL, &rcvall, sizeof(rcvall),
        NULL, 0, &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        int error = WSAGetLastError();
        wchar_t errorMsg[256];
        swprintf_s(errorMsg, L"Failed to set RCVALL mode. Error code: %d", error);
        MessageBox(NULL, errorMsg, L"Error", MB_OK | MB_ICONERROR);
        closesocket(rawSocket);
        WSACleanup();
        return false;
    }

    return true;
}

std::wstring PacketInterceptor::ResolveDestination(const std::wstring& ip) {
    static const std::unordered_map<std::wstring, std::wstring> knownServices = {
        {L"172.217.", L"Google"},
        {L"13.107.", L"Microsoft"},
    };

    for (const auto& service : knownServices) {
        if (ip.find(service.first) == 0) {
            return service.second;
        }
    }

    return L"Unknown";
}

void PacketInterceptor::UpdateConnection(const PacketInfo& info) {
    ConnectionKey key{ info.sourceIP, info.destIP, info.protocol };

    {
        std::lock_guard<std::mutex> lock(connectionsMutex);

        auto& conn = connections[key];
        conn.packetCount++;
        conn.lastSeen = info.time;
        conn.lastUpdate = time(nullptr);

        if (conn.description.empty()) {
            conn.description = ResolveDestination(info.destIP);
        }

        // Очистка старых соединений
        time_t now = time(nullptr);
        for (auto it = connections.begin(); it != connections.end();) {
            if (now - it->second.lastUpdate > 300) {
                it = connections.erase(it);
            }
            else {
                ++it;
            }
        }
    }
}

void PacketInterceptor::ProcessPacket(const char* buffer, int length) {
    if (length < sizeof(IPHeader)) return;

    const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(buffer);

    PacketInfo info;

    // Получаем текущее время
    time_t now = time(nullptr);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    wchar_t timeStr[64];
    swprintf_s(timeStr, L"%04d-%02d-%02d %02d:%02d:%02d",
        timeinfo.tm_year + 1900,
        timeinfo.tm_mon + 1,
        timeinfo.tm_mday,
        timeinfo.tm_hour,
        timeinfo.tm_min,
        timeinfo.tm_sec);
    info.time = timeStr;

    // Преобразуем IP адреса
    char sourceIP[46], destIP[46];  // Увеличиваем буфер для IPv6
    void* srcAddr = const_cast<void*>(reinterpret_cast<const void*>(&ipHeader->sourceIP));
    void* dstAddr = const_cast<void*>(reinterpret_cast<const void*>(&ipHeader->destIP));

    inet_ntop(AF_INET, srcAddr, sourceIP, sizeof(sourceIP));
    inet_ntop(AF_INET, dstAddr, destIP, sizeof(destIP));

    // Конвертируем в широкие строки
    wchar_t wsourceIP[46], wdestIP[46];
    mbstowcs_s(nullptr, wsourceIP, sourceIP, _countof(wsourceIP));
    mbstowcs_s(nullptr, wdestIP, destIP, _countof(wdestIP));

    info.sourceIP = wsourceIP;
    info.destIP = wdestIP;
    info.protocol = GetProtocolName(static_cast<IPPROTO>(ipHeader->protocol));
    info.action = L"Allowed";

    // Обновляем информацию о соединении
    UpdateConnection(info);

    bool shouldNotify = false;
    {
        std::lock_guard<std::mutex> lock(connectionsMutex);
        auto it = connections.find(ConnectionKey{ info.sourceIP, info.destIP, info.protocol });
        if (it != connections.end()) {
            shouldNotify = (it->second.packetCount == 1 || it->second.packetCount % 100 == 0);
        }
    }

    if (shouldNotify && packetCallback) {
        packetCallback(info);
    }
}


bool PacketInterceptor::StartCapture() {
    if (isRunning) {
        return false;
    }

    // Принудительно закрываем старый сокет и инициализируем новый
    if (rawSocket != INVALID_SOCKET) {
        closesocket(rawSocket);
        rawSocket = INVALID_SOCKET;
    }

    // Переинициализируем сокет
    if (!Initialize()) {
        return false;
    }

    isRunning = true;

    captureThreadHandle = CreateThread(
        NULL,
        0,
        CaptureThread,
        this,
        0,
        NULL
    );

    if (captureThreadHandle == NULL) {
        isRunning = false;
        closesocket(rawSocket);
        rawSocket = INVALID_SOCKET;
        return false;
    }

    return true;
}

void PacketInterceptor::StopCapture() {
    if (!isRunning) return;

    isRunning = false;

    // Закрываем сокет, чтобы прервать recv()
    if (rawSocket != INVALID_SOCKET) {
        shutdown(rawSocket, SD_BOTH);
        closesocket(rawSocket);
        rawSocket = INVALID_SOCKET;
    }

    if (captureThreadHandle != NULL) {
        // Ждем завершения потока с таймаутом
        if (WaitForSingleObject(captureThreadHandle, 1000) == WAIT_TIMEOUT) {
            // Если поток не завершился за секунду, принудительно завершаем его
            TerminateThread(captureThreadHandle, 0);
        }
        CloseHandle(captureThreadHandle);
        captureThreadHandle = NULL;
    }
}

DWORD WINAPI PacketInterceptor::CaptureThread(LPVOID param) {
    PacketInterceptor* interceptor = static_cast<PacketInterceptor*>(param);
    char buffer[65536];
    int timeout = 100; // 100 мс таймаут

    // Устанавливаем таймаут для recv
    setsockopt(interceptor->rawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    while (interceptor->isRunning) {
        int bytesRead = recv(interceptor->rawSocket, buffer, sizeof(buffer), 0);
        if (bytesRead > 0) {
            interceptor->ProcessPacket(buffer, bytesRead);
        }
        else if (bytesRead == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK && error != WSAETIMEDOUT) {
                if (interceptor->isRunning) { // Выводим ошибку только если это не плановая остановка
                    wchar_t errorMsg[256];
                    swprintf_s(errorMsg, L"Socket error: %d\n", error);
                    OutputDebugString(errorMsg);
                }
                break;
            }
        }
        Sleep(1); // Небольшая задержка
    }

    return 0;
}


