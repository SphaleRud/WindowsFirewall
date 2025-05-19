#define HAVE_REMOTE
#define WPCAP
#include <SDKDDKVer.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define inline __inline
#include <pcap.h>
#undef inline
#include <netioapi.h>
#include <timeapi.h>
#include <iphlpapi.h>
#include "packetinterceptor.h"
#include "logger.h"
#include <psapi.h> 
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define PCAP_NETMASK_UNKNOWN    0xffffffff


PacketInterceptor::PacketInterceptor()
    : handle(nullptr)
    , isCapturing(false)
    , isRunning(false)
    , rawSocket(INVALID_SOCKET)
{
}

PacketInterceptor::~PacketInterceptor() {
    StopCapture();
    if (handle) {
        pcap_close(handle);
    }
    if (rawSocket != INVALID_SOCKET) {
        closesocket(rawSocket);
    }
    if (isRunning) {
        StopCapture();
    }
    packetCallback = nullptr;
}
bool starts_with(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), str.begin());
}

bool PacketInterceptor::IsLocalAddress(const std::string& ip) const {
    return ip == "127.0.0.1" || starts_with(ip, "127.");
}

bool PacketInterceptor::IsPrivateNetworkAddress(const std::string& ip) const {
    // Проверяем принадлежность к частным диапазонам IP-адресов
    if (starts_with(ip, "192.168.") ||  // 192.168.0.0 - 192.168.255.255
        starts_with(ip, "10.")) {        // 10.0.0.0 - 10.255.255.255
        return true;
    }

    // Проверка диапазона 172.16.0.0 - 172.31.255.255
    if (starts_with(ip, "172.")) {
        try {
            size_t pos = ip.find('.', 4);
            if (pos != std::string::npos) {
                int secondOctet = std::stoi(ip.substr(4, pos - 4));
                if (secondOctet >= 16 && secondOctet <= 31) {
                    return true;
                }
            }
        }
        catch (...) {
            return false;
        }
    }

    return false;
}

PacketDirection PacketInterceptor::DeterminePacketDirection(const std::string& sourceIp) const {
    if (IsLocalAddress(sourceIp) || IsPrivateNetworkAddress(sourceIp)) {
        return PacketDirection::Outgoing;
    }
    return PacketDirection::Incoming;
}

bool GetProcessInfoByPortAndProto(uint16_t port, const std::string& proto, uint32_t& pid, std::string& pname) {
    pid = 0;
    pname = "Unknown";

    if (proto == "TCP") {
        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<char> buffer(size);
        auto* table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
        if (GetExtendedTcpTable(table, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                if (ntohs(table->table[i].dwLocalPort) == port) {
                    pid = table->table[i].dwOwningPid;
                    break;
                }
            }
        }
    }
    else if (proto == "UDP") {
        DWORD size = 0;
        GetExtendedUdpTable(nullptr, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        std::vector<char> buffer(size);
        auto* table = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(buffer.data());
        if (GetExtendedUdpTable(table, &size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                if (ntohs(table->table[i].dwLocalPort) == port) {
                    pid = table->table[i].dwOwningPid;
                    break;
                }
            }
        }
    }

    if (pid != 0) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc) {
            wchar_t wname[MAX_PATH] = L"";
            if (GetModuleFileNameExW(hProc, NULL, wname, MAX_PATH)) {
                LPCWSTR baseName = PathFindFileNameW(wname);
                char mbname[MAX_PATH] = "";
                WideCharToMultiByte(CP_UTF8, 0, baseName, -1, mbname, MAX_PATH, NULL, NULL);
                pname = std::string(mbname);
            }
            CloseHandle(hProc);
        }
    }
    return pid != 0;
}

std::string PacketInterceptor::GetConnectionDescription(const PacketInfo& info) const {
    std::lock_guard<std::mutex> lock(mutex);

    // Формируем ключ для поиска в connections
    std::string key = info.sourceIp + ":" + std::to_string(info.sourcePort) + "-" +
        info.destIp + ":" + std::to_string(info.destPort);

    // Ищем существующее описание
    auto it = connections.find(key);
    if (it != connections.end()) {
        return it->second;
    }

    // Создаем новое описание если не нашли существующее
    std::string description = info.destIp + ":" + std::to_string(info.destPort);
    description += " (" + ResolveDestination(info.destIp) + ")";

    return description;
}

bool PacketInterceptor::SetCurrentAdapter(const std::string& name) {
    if (isCapturing) {
        StopCapture();
    }

    currentAdapter = name;
    return true;
}

// Методы для работы с протоколами и адаптерами
std::string PacketInterceptor::GetProtocolName(unsigned char protocol) {  // Изменен тип параметра
    switch (protocol) {
    case IPPROTO_TCP:  // 6
        return "TCP";
    case IPPROTO_UDP:  // 17
        return "UDP";
    case IPPROTO_ICMP: // 1
        return "ICMP";
    case IPPROTO_IGMP: // 2
        return "IGMP";
    case IPPROTO_IPV6: // 41
        return "IPv6";
    case IPPROTO_IPV4: // 4
        return "IPv4";
    case IPPROTO_RAW:  // 255
        return "RAW";
    case IPPROTO_IP:   // 0
        return "IP";
        // Дополнительные протоколы по их числовым значениям
    case 7:
        return "ISO TP4";
    case 20:
        return "HMP";
    case 44:
        return "FRAG";
    case 53:
        return "SWIPE";
    case 60:
        return "IPv6 Destination Options";
    case 61:
        return "Any Host Internal Protocol";
    case 62:
        return "CFTP (CFTP)";
    case 64:
        return "SATNET and Backroom EXPAK";
    case 82:
        return "VRRP";
    case 92:
        return "MTP";
    case 93:
        return "AX.25 Frames";
    case 101:
        return "PIPE";
    case 104:
        return "IPX in IP";
    case 130:
        return "SNP";
    case 170:
        return "Ethernet-over-IP";
    case 181:
        return "L2TPv3";
    case 228:
        return "GMTP";
    case 236:
        return "Reserved";
    case 9:
        return "IGRP";
    case 21:
        return "XNS-IDP";
    case 108:
        return "IPComp";
    case 173:
        return "DCCP";
    case 187:
        return "UDP-Lite";
    case 193:
        return "SCPS";
    case 200:
        return "IPv6-Opts";
    case 225:
        return "FC";
    case 234:
        return "Ethernet";
    case 237:
        return "Mobility Header";
    case 239:
        return "IPLT";
    case 242:
        return "Compaq Peer Protocol";
    case 253:
        return "Use for experimentation and testing";
    case 37:
        return "DDP";
    case 128:
        return "SSCOPMCE";
    case 122:
        return "SM";
    case 172:
        return "VMTP";
    case 50:
        return "ESP (IPSec)";
    case 51:
        return "AH (IPSec)";
    case 47:
        return "GRE";
    case 58:
        return "ICMPv6";
    case 89:
        return "OSPF";
    case 103:
        return "PIM";
    case 112:
        return "VRRP";
    case 132:
        return "SCTP";
    case 136:
        return "UDPLite";
    case 137:
        return "MPLS-in-IP";
    case 115:
        return "L2TP";
    case 113:
        return "PGM";
    default:
        // Для неизвестных протоколов возвращаем их номер
        return "Protocol-" + std::to_string(static_cast<int>(protocol));
    }
}

std::vector<AdapterInfo> PacketInterceptor::GetAdapters() {
    std::vector<AdapterInfo> adapters;
    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Инициализация WinPcap/Npcap
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return adapters;
    }

    // Перебираем все найденные адаптеры
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        AdapterInfo adapter;
        adapter.name = d->name;
        adapter.description = d->description ? d->description : "No description available";
        adapter.isActive = true;

        // Получаем IP адрес адаптера
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                if (inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN)) {
                    adapter.address = ip;
                    break;
                }
            }
        }

        // Добавляем только адаптеры с IP адресами
        if (!adapter.address.empty()) {
            adapters.push_back(adapter);
        }
    }

    // Освобождаем память
    pcap_freealldevs(alldevs);
    return adapters;
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

bool PacketInterceptor::Initialize() {
    isCapturing = false;
    handle = nullptr;
    return true;
}

bool PacketInterceptor::StartCapture(const std::string& adapterIp) {
    if (isRunning) {
        OutputDebugStringA("Capture already running\n");
        return false;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

    // Находим адаптер по IP
    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::string error = "Failed to find devices: " + std::string(errbuf);
        OutputDebugStringA(error.c_str());
        return false;
    }

    pcap_if_t* device = nullptr;
    for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
        for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                char ip[INET_ADDRSTRLEN];
                struct sockaddr_in* sin = (struct sockaddr_in*)a->addr;
                inet_ntop(AF_INET, &(sin->sin_addr), ip, INET_ADDRSTRLEN);
                if (adapterIp == ip) {
                    device = d;
                    break;
                }
            }
        }
        if (device) break;
    }

    if (!device) {
        pcap_freealldevs(alldevs);
        OutputDebugStringA("No matching device found\n");
        return false;
    }

    std::string deviceName = device->name;
    OutputDebugStringA(("Opening device: " + deviceName + "\n").c_str());

    // Открываем устройство для статистики чтобы проверить его работоспособность
    pcap_t* testHandle = pcap_open_live(device->name, 65536, 0, 1000, errbuf);
    if (!testHandle) {
        std::string error = "Failed to open device for testing: " + std::string(errbuf);
        OutputDebugStringA(error.c_str());
        pcap_freealldevs(alldevs);
        return false;
    }

    // Проверяем статистику
    struct pcap_stat stats;
    if (pcap_stats(testHandle, &stats) == 0) {
        OutputDebugStringA(("Initial stats - Received: " + std::to_string(stats.ps_recv) +
            ", Dropped: " + std::to_string(stats.ps_drop) +
            ", Interface dropped: " + std::to_string(stats.ps_ifdrop) + "\n").c_str());
    }
    pcap_close(testHandle);

    // Теперь открываем для реального захвата
    handle = pcap_open_live(
        device->name,
        65536,          // snaplen
        1,              // promiscuous mode
        50,             // read timeout - уменьшаем до 50мс
        errbuf
    );

    pcap_freealldevs(alldevs);

    if (!handle) {
        std::string error = "Failed to open device for capture: " + std::string(errbuf);
        OutputDebugStringA(error.c_str());
        return false;
    }

    // Проверяем тип канального уровня
    int linkType = pcap_datalink(handle);
    OutputDebugStringA(("Link type: " + std::to_string(linkType) + "\n").c_str());

    // Устанавливаем буфер большего размера
    if (pcap_setbuff(handle, 512000) != 0) {
        OutputDebugStringA("Warning: Failed to set buffer size\n");
    }

    // Устанавливаем режим буферизации
    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        OutputDebugStringA(("Warning: Failed to set nonblocking mode: " + std::string(errbuf) + "\n").c_str());
    }

    // Компилируем и устанавливаем фильтр
    struct bpf_program fcode;
    // Расширяем фильтр для захвата всех интересующих протоколов
    const char* filter = "tcp or udp";
    if (pcap_compile(handle, &fcode, filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
        std::string error = "Failed to compile filter: " + std::string(pcap_geterr(handle));
        OutputDebugStringA(error.c_str());
        pcap_close(handle);
        handle = nullptr;
        return false;
    }

    if (pcap_setfilter(handle, &fcode) < 0) {
        std::string error = "Failed to set filter: " + std::string(pcap_geterr(handle));
        OutputDebugStringA(error.c_str());
        pcap_close(handle);
        handle = nullptr;
        return false;
    }

    pcap_freecode(&fcode);

    isRunning = true;
    try {
        captureThread = std::thread(CaptureThread, this);
        OutputDebugStringA("Capture thread started\n");
        return true;
    }
    catch (const std::exception& e) {
        isRunning = false;
        if (handle) {
            pcap_close(handle);
            handle = nullptr;
        }
        std::string error = "Failed to start capture thread: " + std::string(e.what()) + "\n";
        OutputDebugStringA(error.c_str());
        return false;
    }
}


bool PacketInterceptor::StopCapture() {
    if (!isRunning) return false;

    // Сначала останавливаем поток
    isRunning = false;

    // Прерываем pcap_loop если он используется
    if (handle) {
        pcap_breakloop(handle);
    }

    // Ждем завершения потока
    if (captureThread.joinable()) {
        captureThread.join();
    }

    // Закрываем handle
    if (handle) {
        pcap_close(handle);
        handle = nullptr;
    }

    return true;
}


void PacketInterceptor::CaptureThread(PacketInterceptor* interceptor) {
    try {
        OutputDebugStringA("Capture thread starting\n");
        struct pcap_pkthdr* header;
        const u_char* packet;
        int timeouts = 0; // Счетчик таймаутов для отладки

        while (interceptor->isRunning) {
            if (!interceptor->handle) {
                OutputDebugStringA("Handle is null in capture thread\n");
                break;
            }

            int result = pcap_next_ex(interceptor->handle, &header, &packet);
            switch (result) {
            case 1:  // Пакет успешно захвачен
                OutputDebugStringA("Packet captured\n");
                timeouts = 0; // Сбрасываем счетчик таймаутов
                interceptor->ProcessPacket(header, packet);
                break;

            case 0:  // Таймаут
                timeouts++;
                if (timeouts % 100 == 0) { // Логируем каждый сотый таймаут
                    OutputDebugStringA(("Timeouts: " + std::to_string(timeouts) + "\n").c_str());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;

            case -1: // Ошибка чтения
            {
                std::string error = "Error reading packet: ";
                error += pcap_geterr(interceptor->handle);
                OutputDebugStringA((error + "\n").c_str());
                if (!interceptor->isRunning) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }

            case -2: // EOF или прерывание
                OutputDebugStringA("Capture EOF or interrupted\n");
                if (!interceptor->isRunning) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;

            default:
                OutputDebugStringA(("Unknown result from pcap_next_ex: " + std::to_string(result) + "\n").c_str());
                if (!interceptor->isRunning) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
        }
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("Capture thread exception: " + std::string(e.what()) + "\n").c_str());
    }
    catch (...) {
        OutputDebugStringA("Unknown exception in capture thread\n");
    }

    OutputDebugStringA("Capture thread ending\n");
}


std::string PacketInterceptor::ResolveDestination(const std::string& ip) const {
    char host[NI_MAXHOST];
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr));
    sa.sin_port = 0;

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa),
        host, NI_MAXHOST,
        NULL, 0,
        NI_NAMEREQD) == 0) {
        return std::string(host);
    }

    return ip;
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
    return sourceIp == currentAdapter;
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

void PacketInterceptor::ProcessPacket(const pcap_pkthdr* header, const u_char* packet) {
    // Проверка входных параметров
    if (!header || !packet || !packetCallback) {
        OutputDebugStringA("ProcessPacket: Invalid parameters\n");
        return;
    }
    try {

        size_t len = header->len;
        // --- Ограничение на поток пакетов ---
        static std::atomic<size_t> packetCount = 0;
        static std::atomic<time_t> lastTime = 0;
        time_t now = time(nullptr);
        if (now != lastTime) {
            lastTime = now;
            packetCount = 0;
        }
        if (++packetCount > 500) { // Не более 500 пакетов в секунду
            return;
        }

        int ipOffset = 0;
        bool hasEthernet = false;

        // --- Определяем, есть ли Ethernet header ---
        if (len >= 14) {
            uint16_t etherType = ntohs(*(uint16_t*)(packet + 12));
            if (etherType == 0x0800 || etherType == 0x86DD) {
                hasEthernet = true;
                ipOffset = 14;
            }
        }
        if (!hasEthernet) {
            ipOffset = 0;
            if (len < 20) return; // слишком короткий для IP
        }

        const u_char* ipStart = packet + ipOffset;

        // --- Определяем версию IP ---
        uint8_t version = (ipStart[0] >> 4) & 0x0F;
        if (version == 4) {
            if (len < ipOffset + 20) return;
            const IPHeader* ipHeader = reinterpret_cast<const IPHeader*>(ipStart);

            PacketInfo info = {};
            info.processId = 0;
            info.processName = "Unknown";

            // Время
            SYSTEMTIME st = {};
            GetSystemTime(&st);
            char timeBuffer[32] = {};
            sprintf_s(timeBuffer, sizeof(timeBuffer), "%04d-%02d-%02d %02d:%02d:%02d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            info.time = timeBuffer;

            // IP
            char srcIP[INET_ADDRSTRLEN] = {}, dstIP[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &(ipHeader->sourceIP), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->destIP), dstIP, INET_ADDRSTRLEN);
            info.sourceIp = srcIP;
            info.destIp = dstIP;

            // Протокол, размер
            info.protocol = GetProtocolName(ipHeader->protocol);
            info.size = header->len;

            info.direction = DeterminePacketDirection(srcIP);

            // Порты
            int ipHeaderLength = (ipHeader->headerLength & 0x0F) * 4;
            info.sourcePort = 0;
            info.destPort = 0;
            if (ipHeader->protocol == IPPROTO_TCP) {
                if (len >= ipOffset + ipHeaderLength + sizeof(TCPHeader)) {
                    const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(ipStart + ipHeaderLength);
                    info.sourcePort = ntohs(tcp->sourcePort);
                    info.destPort = ntohs(tcp->destPort);
                }
            }
            else if (ipHeader->protocol == IPPROTO_UDP) {
                if (len >= ipOffset + ipHeaderLength + sizeof(UDPHeader)) {
                    const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(ipStart + ipHeaderLength);
                    info.sourcePort = ntohs(udp->sourcePort);
                    info.destPort = ntohs(udp->destPort);
                }
            }

            // PID и имя процесса
            uint32_t pid = 0;
            std::string pname = "Unknown";
            uint16_t localPort = (info.direction == PacketDirection::Outgoing) ? info.sourcePort : info.destPort;
            GetProcessInfoByPortAndProto(localPort, info.protocol, pid, pname);
            info.processId = pid;
            info.processName = pname;

            if (info.sourceIp.empty()) info.sourceIp = "Unknown";
            if (info.destIp.empty()) info.destIp = "Unknown";
            if (info.protocol.empty()) info.protocol = "Unknown";
            if (info.processName.empty()) info.processName = "Unknown";
            if (info.time.empty()) info.time = "Unknown";

            // Callback
            try {
                packetCallback(info);
            }
            catch (const std::exception& e) {
                OutputDebugStringA(("ProcessPacket callback error: " + std::string(e.what()) + "\n").c_str());
            }
        }
        else if (version == 6) {
            // Можно реализовать разбор IPv6
            // Пока просто пропускаем такие пакеты
            return;
        }
        else {
            // Неизвестный протокол
            return;
        }
    }
    catch (const std::exception& e) {
        OutputDebugStringA(("ProcessPacket error: " + std::string(e.what()) + "\n").c_str());
    }
    catch (...) {
        OutputDebugStringA("ProcessPacket: Unknown error occurred\n");
    }
}