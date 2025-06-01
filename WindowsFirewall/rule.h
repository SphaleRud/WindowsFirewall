#pragma once
#include "firewall_types.h"
#include <string>

// Добавляем новые перечисления для типов IP и портов
enum class IpMatchType {
    ANY,        // Любой IP
    SPECIFIC    // Конкретный IP
};

enum class PortMatchType {
    ANY,        // Любой порт
    SPECIFIC    // Конкретный порт
};

class Rule {
public:
    Rule()
        : id(0)
        , protocol(Protocol::ANY)
        , sourcePortType(PortMatchType::ANY)
        , destPortType(PortMatchType::ANY)
        , sourcePort(0)
        , destPort(0)
        , sourceIpType(IpMatchType::ANY)
        , destIpType(IpMatchType::ANY)
        , action(RuleAction::ALLOW)
        , enabled(true)
        , direction(RuleDirection::Inbound)
    {
    }

    Rule(const Rule& other)
        : id(other.id)
        , name(other.name)
        , description(other.description)
        , protocol(other.protocol)
        , sourceIpType(other.sourceIpType)
        , destIpType(other.destIpType)
        , sourceIp(other.sourceIp)
        , destIp(other.destIp)
        , sourcePortType(other.sourcePortType)
        , destPortType(other.destPortType)
        , sourcePort(other.sourcePort)
        , destPort(other.destPort)
        , appPath(other.appPath)
        , action(other.action)
        , enabled(other.enabled)
        , direction(other.direction)
        , creator(other.creator)
        , creationTime(other.creationTime)
    {
    }

    Rule& operator=(const Rule& other) {
        if (this != &other) {
            id = other.id;
            name = other.name;
            description = other.description;
            protocol = other.protocol;
            sourceIp = other.sourceIp;
            destIp = other.destIp;
			sourcePortType = other.sourcePortType;
			destPortType = other.destPortType;
            sourcePort = other.sourcePort;
            destPort = other.destPort;
            appPath = other.appPath;
            action = other.action;
            enabled = other.enabled;
            direction = other.direction;
            creator = other.creator;
            creationTime = other.creationTime;
        }
        return *this;
    }

    int id;
    std::string name;
    std::string description;
    Protocol protocol;

    // IP параметры
    IpMatchType sourceIpType;
    IpMatchType destIpType;
    std::string sourceIp;
    std::string destIp;

    // Параметры портов
    PortMatchType sourcePortType;
    PortMatchType destPortType;
    int sourcePort;
    int destPort;

    std::string appPath;
    RuleAction action;
    bool enabled;
    RuleDirection direction;
    std::string creator;
    std::string creationTime;
};