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

bool PacketInterceptor::SwitchAdapter(const std::string& ipAddress) {
    try {
        // Останавливаем текущий захват если есть
        StopCapture();

        // Очищаем текущие ресурсы если есть
        // Инициализируем новый адаптер

        return true; // возвращаем true только если смена прошла успешно
    }
    catch (const std::exception&) {
        return false;
    }
}

bool PacketInterceptor::IsWifiAdapter(PIP_ADAPTER_ADDRESSES adapter) {
    return adapter->IfType == IF_TYPE_IEEE80211;
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

std::string PacketInterceptor::ResolveDestination(const std::wstring& ip) {
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
        conn.lastSeen = info.timestamp;
        conn.lastUpdate = time(nullptr);

        if (conn.description.empty()) {
            conn.description = ResolveDestination(info.destIp);
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

std::vector<NetworkAdapter> PacketInterceptor::GetNetworkAdapters() {
    std::vector<NetworkAdapter> adapters;

    // Получаем размер буфера
    ULONG bufferSize = 0;
    if (GetAdaptersInfo(nullptr, &bufferSize) != ERROR_BUFFER_OVERFLOW) {
        return adapters;
    }

    // Выделяем буфер
    std::vector<BYTE> buffer(bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    // Получаем информацию об адаптерах
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR) {
        for (PIP_ADAPTER_INFO pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
            // Пропускаем неактивные адаптеры
            if (pAdapter->Type == MIB_IF_TYPE_LOOPBACK) {
                continue;
            }

            NetworkAdapter adapter;

            // Конвертируем строки в wide
            int len = MultiByteToWideChar(CP_ACP, 0, pAdapter->Description, -1, nullptr, 0);
            std::vector<wchar_t> wDescription(len);
            MultiByteToWideChar(CP_ACP, 0, pAdapter->Description, -1, wDescription.data(), len);
            adapter.description = WideToAnsi(wDescription.data());

            len = MultiByteToWideChar(CP_ACP, 0, pAdapter->AdapterName, -1, nullptr, 0);
            std::vector<wchar_t> wName(len);
            MultiByteToWideChar(CP_ACP, 0, pAdapter->AdapterName, -1, wName.data(), len);
            adapter.name = WideToAnsi(wName.data());

            adapter.ipAddress = pAdapter->IpAddressList.IpAddress.String;
            adapter.isWifi = (pAdapter->Type == IF_TYPE_IEEE80211);

            adapters.push_back(adapter);
        }
    }

    return adapters;
}

bool PacketInterceptor::IsLocalAddress(const std::string& ipAddress) {
    // Проверяем специальные диапазоны
    if (ipAddress.substr(0, 3) == "127" ||    // Localhost
        ipAddress.substr(0, 3) == "10." ||     // Private network
        ipAddress.substr(0, 7) == "192.168" || // Private network
        ipAddress.substr(0, 7) == "169.254")   // Link-local
    {
        return true;
    }

    // Сравниваем с адресами адаптеров
    std::vector<NetworkAdapter> adapters = GetNetworkAdapters();
    for (const auto& adapter : adapters) {
        if (adapter.ipAddress == ipAddress) {
            return true;
        }
    }

    return false;
}

std::string PacketInterceptor::GetProcessNameById(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        char processName[MAX_PATH] = "";
        DWORD size = MAX_PATH;

        if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
            CloseHandle(hProcess);
            // Извлекаем только имя файла из полного пути
            std::string fullPath(processName);
            size_t pos = fullPath.find_last_of("\\");
            if (pos != std::string::npos) {
                return fullPath.substr(pos + 1);
            }
            return fullPath;
        }
        CloseHandle(hProcess);
    }
    return "Unknown";
}

DWORD PacketInterceptor::GetProcessIdByPort(WORD port, const std::string& protocol) {
    if (port == 0) return 0;

    if (protocol == "TCP") {
        MIB_TCPTABLE_OWNER_PID* tcpTable = nullptr;
        DWORD size = 0;

        if (GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) ==
            ERROR_INSUFFICIENT_BUFFER) {
            tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
            if (tcpTable) {
                if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) ==
                    NO_ERROR) {
                    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
                        if (ntohs((u_short)tcpTable->table[i].dwLocalPort) == port) {
                            DWORD processId = tcpTable->table[i].dwOwningPid;
                            free(tcpTable);
                            return processId;
                        }
                    }
                }
                free(tcpTable);
            }
        }
    }
    else if (protocol == "UDP") {
        MIB_UDPTABLE_OWNER_PID* udpTable = nullptr;
        DWORD size = 0;

        if (GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) ==
            ERROR_INSUFFICIENT_BUFFER) {
            udpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(size);
            if (udpTable) {
                if (GetExtendedUdpTable(udpTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) ==
                    NO_ERROR) {
                    for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
                        if (ntohs((u_short)udpTable->table[i].dwLocalPort) == port) {
                            DWORD processId = udpTable->table[i].dwOwningPid;
                            free(udpTable);
                            return processId;
                        }
                    }
                }
                free(udpTable);
            }
        }
    }

    return 0;
}

void PacketInterceptor::ProcessPacket(const char* data, int size) {
    PacketInfo info;

    // Предполагаем, что data указывает на начало IP заголовка
    IPHeader* ipHeader = (IPHeader*)data;

    // Получаем IP адреса
    in_addr srcAddr, destAddr;
    srcAddr.s_addr = ipHeader->sourceIP;
    destAddr.s_addr = ipHeader->destIP;
    info.sourceIp = inet_ntoa(srcAddr);
    info.destIp = inet_ntoa(destAddr);

    // Определяем протокол
    switch (ipHeader->protocol) {
    case IPPROTO_TCP: {
        info.protocol = "TCP";
        TCPHeader* tcpHeader = (TCPHeader*)(data + sizeof(IPHeader));
        info.sourcePort = ntohs(tcpHeader->sourcePort);
        info.destPort = ntohs(tcpHeader->destPort);
        break;
    }
    case IPPROTO_UDP: {
        info.protocol = "UDP";
        UDPHeader* udpHeader = (UDPHeader*)(data + sizeof(IPHeader));
        info.sourcePort = ntohs(udpHeader->sourcePort);
        info.destPort = ntohs(udpHeader->destPort);
        break;
    }
    case IPPROTO_ICMP:
        info.protocol = "ICMP";
        info.sourcePort = 0;
        info.destPort = 0;
        break;
    default:
        info.protocol = "Unknown";
        info.sourcePort = 0;
        info.destPort = 0;
    }

    // Определяем размер пакета
    info.bytesSent = size;

    // Определяем направление пакета
    if (IsLocalAddress(info.destIp)) {
        info.direction = "IN";
    }
    else {
        info.direction = "OUT";
    }

    // Устанавливаем время
    GetSystemTime(&info.timestamp);

    // Определяем приложение
    DWORD processId = GetProcessIdByPort(info.sourcePort, info.protocol);
    if (processId != 0) {
        info.application = GetProcessNameById(processId);
    }
    else {
        processId = GetProcessIdByPort(info.destPort, info.protocol);
        if (processId != 0) {
            info.application = GetProcessNameById(processId);
        }
        else {
            info.application = "Unknown";
        }
    }

    // Вызываем callback
    if (packetCallback) {
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


