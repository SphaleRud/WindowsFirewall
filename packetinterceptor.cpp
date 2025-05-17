#define HAVE_REMOTE
#define WPCAP
#include <SDKDDKVer.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define inline __inline
#include <pcap.h>
#undef inline
#include <algorithm>
#include <netioapi.h>
#include <timeapi.h>
#include <iphlpapi.h>
#include "packetinterceptor.h"
#include "logger.h"


#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define PCAP_NETMASK_UNKNOWN    0xffffffff


PacketInterceptor::PacketInterceptor()
    : pcapHandle(nullptr)
    , isCapturing(false)
    , isRunning(false)
    , rawSocket(INVALID_SOCKET) {
}

PacketInterceptor::~PacketInterceptor() {
    StopCapture();
    if (pcapHandle) {
        pcap_close(pcapHandle);
    }
    if (rawSocket != INVALID_SOCKET) {
        closesocket(rawSocket);
    }
}

std::string PacketInterceptor::GetConnectionDescription(const PacketInfo& info) const {
    std::lock_guard<std::mutex> lock(mutex);
    std::string key = info.sourceIp + ":" + std::to_string(info.sourcePort) + "-" +
        info.destIp + ":" + std::to_string(info.destPort);

    auto it = connections.find(key);
    if (it != connections.end()) {
        return it->second;
    }

    // Если соединение не найдено, возвращаем базовое описание
    return info.destIp + ":" + std::to_string(info.destPort) + " (" + ResolveDestination(info.destIp) + ")";
}

bool PacketInterceptor::SetCurrentAdapter(const std::string& adapterName) {
    if (isCapturing) {
        StopCapture();
    }

    currentAdapter = adapterName;
    return true;
}

// Методы для работы с протоколами и адаптерами
std::string PacketInterceptor::GetProtocolName(int protocol) const {
    switch (protocol) {
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_ICMP: return "ICMP";
    default: return "Unknown";
    }
}

bool PacketInterceptor::IsWifiAdapter(const std::string& name) const {
    // Преобразуем строку в нижний регистр для поиска
    std::string lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Ищем ключевые слова, указывающие на WiFi адаптер
    return lowerName.find("wireless") != std::string::npos ||
        lowerName.find("wifi") != std::string::npos ||
        lowerName.find("802.11") != std::string::npos;
}

std::vector<NetworkAdapter> PacketInterceptor::GetNetworkAdapters() const {
    std::vector<NetworkAdapter> adapters;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return adapters;
    }

    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        NetworkAdapter adapter;
        adapter.name = d->name;
        adapter.description = d->description ? d->description : "No description available";
        adapters.push_back(adapter);
    }

    pcap_freealldevs(alldevs);
    return adapters;
}

bool PacketInterceptor::IsCapturing() const {
    return isCapturing;
}

bool PacketInterceptor::Initialize() {
    isCapturing = false;
    handle = nullptr;
    return true;
}

bool PacketInterceptor::StartCapture() {
    if (isCapturing || currentAdapter.empty()) {
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(currentAdapter.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        return false;
    }

    isCapturing = true;
    // Запускаем поток для захвата пакетов
    captureThread = std::thread(&PacketInterceptor::CaptureThread, this);
    captureThread.detach();

    return true;
}



bool PacketInterceptor::StopCapture() {
    if (!isCapturing) {
        return false;
    }

    isCapturing = false;
    if (handle) {
        pcap_breakloop(handle);
        pcap_close(handle);
        handle = nullptr;
    }

    return true;
}


void PacketInterceptor::CaptureThread() {
    if (!handle) return;

    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res;

    while (isCapturing && (res = pcap_next_ex(handle, &header, &pkt_data)) >= 0) {
        if (res == 0) continue; // Timeout

        // Обработка пакета
        ProcessPacket(header, pkt_data);
    }
}


std::string PacketInterceptor::ResolveDestination(const std::string& ip) const {
    char host[NI_MAXHOST];
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
        host, NI_MAXHOST,
        NULL, 0,
        NI_NAMEREQD) == 0) {
        return std::string(host);
    }

    return ip; // Возвращаем IP если резолвинг не удался
}
void PacketInterceptor::UpdateConnection(const PacketInfo& info) {
    std::lock_guard<std::mutex> lock(mutex);
    std::string key = info.sourceIp + ":" + std::to_string(info.sourcePort) + "-" +
        info.destIp + ":" + std::to_string(info.destPort);
    connections[key] = info.processName;
}

std::string PacketInterceptor::GetServiceName(unsigned short port) const {
    auto it = knownServices.find(port);
    return it != knownServices.end() ? it->second : "Unknown";
}

bool PacketInterceptor::IsOutgoingPacket(const std::string& sourceIp) const {
    return sourceIp == currentAdapterIp;
}

std::string PacketInterceptor::GetProcessNameByPort(unsigned short port) {
    // Используем GetExtendedTcpTable для получения информации о процессах
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    std::vector<char> buffer(size);
    PMIB_TCPTABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(&buffer[0]);

    if (GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            if (ntohs(tcpTable->table[i].dwLocalPort) == port) {
                HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, tcpTable->table[i].dwOwningPid);
                if (processHandle) {
                    char processName[MAX_PATH];
                    DWORD size = sizeof(processName);
                    if (QueryFullProcessImageNameA(processHandle, 0, processName, &size)) {
                        CloseHandle(processHandle);
                        return std::string(processName);
                    }
                    CloseHandle(processHandle);
                }
            }
        }
    }

    // Проверяем UDP соединения
    GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    buffer.resize(size);
    PMIB_UDPTABLE_OWNER_PID udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(&buffer[0]);

    if (GetExtendedUdpTable(udpTable, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            if (ntohs(udpTable->table[i].dwLocalPort) == port) {
                HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, udpTable->table[i].dwOwningPid);
                if (processHandle) {
                    char processName[MAX_PATH];
                    DWORD size = sizeof(processName);
                    if (QueryFullProcessImageNameA(processHandle, 0, processName, &size)) {
                        CloseHandle(processHandle);
                        return std::string(processName);
                    }
                    CloseHandle(processHandle);
                }
            }
        }
    }

    return "Unknown";
}

void PacketInterceptor::ProcessPacket(const u_char* packet, int len) {
    if (!packet || len < sizeof(IPHeader)) {
        return;
    }

    PacketInfo info;
    info.timestamp = time(nullptr);
    info.size = len;

    // Получаем заголовок IP пакета
    const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(packet);

    // Преобразуем IP адреса
    struct in_addr source, dest;
    source.s_addr = ipHeader->sourceIP;
    dest.s_addr = ipHeader->destIP;

    char sourceIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source, sourceIP, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dest, destIP, INET_ADDRSTRLEN);

    info.sourceIp = sourceIP;
    info.destIp = destIP;
    info.protocol = GetProtocolName(ipHeader->protocol);

    // Определяем смещение для доступа к данным протокола транспортного уровня
    int ipHeaderLength = ipHeader->headerLength * 4;

    // Обрабатываем TCP пакеты
    if (ipHeader->protocol == IPPROTO_TCP && len >= (ipHeaderLength + sizeof(TCPHeader))) {
        const TCPHeader* tcpHeader = reinterpret_cast<const TCPHeader*>(packet + ipHeaderLength);
        info.sourcePort = ntohs(tcpHeader->sourcePort);
        info.destPort = ntohs(tcpHeader->destPort);

        // Анализ флагов TCP
        std::string flags;
        if (tcpHeader->flags & 0x01) flags += "FIN ";
        if (tcpHeader->flags & 0x02) flags += "SYN ";
        if (tcpHeader->flags & 0x04) flags += "RST ";
        if (tcpHeader->flags & 0x08) flags += "PSH ";
        if (tcpHeader->flags & 0x10) flags += "ACK ";
        if (tcpHeader->flags & 0x20) flags += "URG ";
        info.flags = flags;
        info.direction = IsOutgoingPacket(info.sourceIp) ? "Outgoing" : "Incoming";

    }
    // Обрабатываем UDP пакеты
    else if (ipHeader->protocol == IPPROTO_UDP && len >= (ipHeaderLength + sizeof(UDPheader))) {
        const UDPheader* udpHeader = reinterpret_cast<const UDPheader*>(packet + ipHeaderLength);
        info.sourcePort = ntohs(udpHeader->source_port);
        info.destPort = ntohs(udpHeader->dest_port);
        info.flags = "";  // UDP не имеет флагов
        info.direction = IsOutgoingPacket(info.sourceIp) ? "Outgoing" : "Incoming";

    }
    // Обрабатываем ICMP пакеты
    else if (ipHeader->protocol == IPPROTO_ICMP && len >= (ipHeaderLength + sizeof(icmp_header))) {
        const icmp_header* icmpHeader = reinterpret_cast<const icmp_header*>(packet + ipHeaderLength);
        info.sourcePort = 0;
        info.destPort = 0;

        // Определение типа ICMP сообщения
        std::string icmpType;
        switch (icmpHeader->type) {
        case ICMP_ECHOREPLY: icmpType = "Echo Reply"; break;
        case ICMP_ECHO: icmpType = "Echo Request"; break;
        case ICMP_DEST_UNREACH: icmpType = "Destination Unreachable"; break;
        case ICMP_TIME_EXCEEDED: icmpType = "Time Exceeded"; break;
        default: icmpType = "Other ICMP Type: " + std::to_string(icmpHeader->type);
        }
        info.flags = icmpType;
        info.direction = IsOutgoingPacket(info.sourceIp) ? "Outgoing" : "Incoming";
        info.processName = "System";
    }

    // Пытаемся определить имя процесса
    if (info.processName.empty()) {
        info.processName = GetProcessNameByPort(info.sourcePort);
    }

    // Обновляем информацию о соединении
    UpdateConnection(info);

    // Вызываем callback с информацией о пакете
    if (packetCallback) {
        packetCallback(info);
    }
}