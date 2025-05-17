#include "main_window.h"
#include <iomanip>
#include <sstream>
#include "connection_tracker.h"

std::string ConnectionTracker::DetermineService(uint16_t port, const std::string& protocol) {
    // Определение известных сервисов по портам
    static const std::map<uint16_t, std::string> knownPorts = {
        {80, "HTTP"}, {443, "HTTPS"}, {53, "DNS"},
        {21, "FTP"}, {22, "SSH"}, {23, "Telnet"},
        {25, "SMTP"}, {110, "POP3"}, {143, "IMAP"},
        {3389, "RDP"}, {3306, "MySQL"}, {1433, "MSSQL"},
        {5432, "PostgreSQL"}, {27017, "MongoDB"},
        {6379, "Redis"}, {5672, "AMQP"},
        {5222, "XMPP"}, {5269, "XMPP Server"},
        {1194, "OpenVPN"}, {1701, "L2TP"},
        {1723, "PPTP"}, {500, "ISAKMP"},
        {4500, "IPSec NAT"}
    };

    auto it = knownPorts.find(port);
    if (it != knownPorts.end()) {
        return it->second;
    }

    // Если порт неизвестен, возвращаем порт и протокол
    std::stringstream ss;
    ss << protocol << ":" << port;
    return ss.str();
}

void ConnectionTracker::AddPacket(const PacketInfo& packet) {
    ConnectionKey key{
        packet.sourceIp,
        packet.destIp,
        packet.sourcePort,
        packet.destPort,
        packet.protocol,
        packet.direction
    };

    auto& info = connections[key];
    info.packetsCount++;
    info.bytesSent += packet.bytesSent;
    info.lastSeen = packet.timestamp;
    info.application = packet.application;

    if (info.service.empty()) {
        info.service = DetermineService(packet.destPort, packet.protocol);
    }
}

void ConnectionTracker::Clear() {
    connections.clear();
}
